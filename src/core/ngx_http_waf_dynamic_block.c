#include "ngx_http_waf_dynamic_block.h"
#include "ngx_http_waf_action.h"
#include "ngx_http_waf_module_v2.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 外部声明模块 */
extern ngx_module_t ngx_http_waf_module;

/*
 * ================================================================
 *  动态信誉与共享内存模块（M5）
 *  - 红黑树存储IP节点、LRU淘汰策略
 *  - 评分窗口、封禁阈值、过期检查
 *  - 并发控制：shpool->mutex
 * ================================================================
 */

/* 前向声明：LRU淘汰函数 */
static ngx_uint_t waf_dyn_evict_nodes(waf_dyn_shm_ctx_t *ctx, ngx_uint_t num_to_evict,
                                      ngx_log_t *log);

/* 前向声明：红黑树查找 */
static waf_dyn_ip_node_t *waf_dyn_lookup_ip(waf_dyn_shm_ctx_t *ctx, ngx_uint_t ip_addr);

void waf_dyn_init_shm_zone(ngx_cycle_t *cycle)
{
  (void)cycle; /* 当前为空实现：shm由main_conf初始化时自动调用init回调 */
}

void waf_dyn_score_add(ngx_http_request_t *r, ngx_uint_t delta)
{
  ngx_http_waf_main_conf_t *mcf;
  ngx_http_waf_loc_conf_t *lcf;
  ngx_http_waf_ctx_t *ctx;
  waf_dyn_shm_ctx_t *shm_ctx;
  waf_dyn_ip_node_t *ip_node;
  ngx_uint_t ip_addr;
  ngx_msec_t now;
  ngx_uint_t evicted;

  if (r == NULL)
    return;

  mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
  lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
  ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

  /* 未启用动态封禁或shm未初始化 */
  if (mcf == NULL || lcf == NULL || ctx == NULL || mcf->shm_zone == NULL ||
      mcf->shm_zone->data == NULL || mcf->dyn_block_threshold == 0) {
    return;
  }

  shm_ctx = (waf_dyn_shm_ctx_t *)mcf->shm_zone->data;
  ip_addr = ctx->client_ip; /* ctx中的client_ip（网络字节序uint32_t） */
  if (ip_addr == 0) {
    return; /* 无效IP */
  }
  /* 使用请求级时间快照，避免单请求内时间割裂 */
  now = (ctx && ctx->request_now_msec > 0) ? ctx->request_now_msec : ngx_current_msec;

  ngx_shmtx_lock(&shm_ctx->shpool->mutex);

  ip_node = waf_dyn_lookup_ip(shm_ctx, ip_addr);

  if (ip_node == NULL) {
    /* 创建新节点 */
    ip_node = ngx_slab_alloc_locked(shm_ctx->shpool, sizeof(waf_dyn_ip_node_t));
    if (ip_node == NULL) {
      /* 尝试淘汰1个节点 */
      evicted = waf_dyn_evict_nodes(shm_ctx, 1, r->connection->log);
      if (evicted > 0) {
        ip_node = ngx_slab_alloc_locked(shm_ctx->shpool, sizeof(waf_dyn_ip_node_t));
      }
      if (ip_node == NULL) {
        ngx_shmtx_unlock(&shm_ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "waf_dyn: slab alloc failed after evict (evicted=%ui)", evicted);
        return;
      }
    }

    ngx_memzero(ip_node, sizeof(waf_dyn_ip_node_t));
    ip_node->ip_addr = ip_addr;
    ip_node->node.key = ip_addr;
    ip_node->score = 0;
    ip_node->window_start_time = now;
    ip_node->last_seen = now;
    ip_node->block_expiry = 0;

    ngx_rbtree_insert(&shm_ctx->rbtree, &ip_node->node);
    ngx_queue_insert_head(&shm_ctx->lru_queue, &ip_node->queue);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "waf_dyn: created new IP node, ip=%uD", ip_addr);
  } else {
    /* 节点存在：移动到LRU头部 */
    ngx_queue_remove(&ip_node->queue);
    ngx_queue_insert_head(&shm_ctx->lru_queue, &ip_node->queue);
    ip_node->last_seen = now;

    /* 检查窗口是否过期（window_size单位：毫秒） */
    if (mcf->dyn_block_window > 0 && (now - ip_node->window_start_time >= mcf->dyn_block_window)) {
      ngx_uint_t prev = (ngx_uint_t)ip_node->score;
      /* 运维日志：信息级 */
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "waf_dyn: window expired for ip=%uD, reset score from %uA", ip_addr, prev);

      /* 请求JSONL：通过动作层包装，使用“条件写入 + DEBUG 级” */
      if (prev > 0) {
        waf_action_log_window_reset(r, mcf, ctx, prev, ip_node->window_start_time, now,
                                    WAF_LOG_COLLECT_LEVEL_GATED, WAF_LOG_DEBUG);
      }

      ip_node->score = 0;
      ip_node->window_start_time = now;
    }
  }

  /* 累加评分（原子操作） */
  ngx_atomic_t old_score = ngx_atomic_fetch_add(&ip_node->score, delta);
  ngx_uint_t new_score = old_score + delta;

  ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "waf_dyn: ip=%uD, score: %ui -> %ui",
                 ip_addr, old_score, new_score);

  /* 检查是否超过阈值且当前未封禁 */
  if (new_score > mcf->dyn_block_threshold &&
      (ip_node->block_expiry == 0 || ip_node->block_expiry <= now)) {
    ip_node->block_expiry = now + mcf->dyn_block_duration;
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "waf_dyn: IP blocked, ip=%uD, score=%ui, threshold=%ui, expiry=%M", ip_addr,
                  new_score, mcf->dyn_block_threshold, ip_node->block_expiry);
  }

  ngx_shmtx_unlock(&shm_ctx->shpool->mutex);
}

ngx_flag_t waf_dyn_is_banned(ngx_http_request_t *r)
{
  ngx_http_waf_main_conf_t *mcf;
  ngx_http_waf_ctx_t *ctx;
  waf_dyn_shm_ctx_t *shm_ctx;
  waf_dyn_ip_node_t *ip_node;
  ngx_uint_t ip_addr;
  ngx_msec_t now;
  ngx_flag_t banned = 0;

  if (r == NULL)
    return 0;

  mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
  ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

  if (mcf == NULL || ctx == NULL || mcf->shm_zone == NULL || mcf->shm_zone->data == NULL) {
    return 0;
  }

  shm_ctx = (waf_dyn_shm_ctx_t *)mcf->shm_zone->data;
  ip_addr = ctx->client_ip; /* 网络字节序 */
  if (ip_addr == 0) {
    return 0; /* 无效IP，不封禁 */
  }
  now = (ctx && ctx->request_now_msec > 0) ? ctx->request_now_msec : ngx_current_msec;

  ngx_shmtx_lock(&shm_ctx->shpool->mutex);

  ip_node = waf_dyn_lookup_ip(shm_ctx, ip_addr);

  if (ip_node != NULL) {
    /* 无论是否封禁都更新LRU */
    ngx_queue_remove(&ip_node->queue);
    ngx_queue_insert_head(&shm_ctx->lru_queue, &ip_node->queue);
    ip_node->last_seen = now;

    if (ip_node->block_expiry > 0) {
      if (ip_node->block_expiry > now) {
        /* 仍在封禁中 */
        banned = 1;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "waf_dyn: ip=%uD is banned, expiry=%M", ip_addr, ip_node->block_expiry);
      } else {
        /* 封禁已过期：重置 */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "waf_dyn: ip=%uD ban expired, reset", ip_addr);
        ip_node->block_expiry = 0;
      }
    }
  }

  ngx_shmtx_unlock(&shm_ctx->shpool->mutex);

  return banned;
}

/* ===== 红黑树查找 ===== */
static waf_dyn_ip_node_t *waf_dyn_lookup_ip(waf_dyn_shm_ctx_t *ctx, ngx_uint_t ip_addr)
{
  ngx_rbtree_node_t *node, *sentinel;
  waf_dyn_ip_node_t *ip_node;

  node = ctx->rbtree.root;
  sentinel = ctx->rbtree.sentinel;

  while (node != sentinel) {
    ip_node = (waf_dyn_ip_node_t *)node;
    if (ip_addr < ip_node->ip_addr) {
      node = node->left;
    } else if (ip_addr > ip_node->ip_addr) {
      node = node->right;
    } else {
      return ip_node; /* 找到 */
    }
  }

  return NULL; /* 未找到 */
}

/* ===== LRU淘汰：从队列尾部淘汰未封禁的节点 ===== */
static ngx_uint_t waf_dyn_evict_nodes(waf_dyn_shm_ctx_t *ctx, ngx_uint_t num_to_evict,
                                      ngx_log_t *log)
{
  ngx_uint_t evicted = 0;
  ngx_queue_t *q;
  waf_dyn_ip_node_t *ip_node;
  ngx_msec_t now = ngx_current_msec;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "waf_dyn: attempting to evict %ui nodes",
                 num_to_evict);

  for (ngx_uint_t i = 0; i < num_to_evict; i++) {
    if (ngx_queue_empty(&ctx->lru_queue)) {
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "waf_dyn: LRU queue empty, cannot evict");
      break;
    }

    /* 获取队列尾部节点（最久未使用） */
    q = ngx_queue_last(&ctx->lru_queue);
    ip_node = ngx_queue_data(q, waf_dyn_ip_node_t, queue);

    /* 策略：不淘汰当前仍在封禁中的IP */
    if (ip_node->block_expiry > now) {
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                     "waf_dyn: LRU candidate ip=%uD is banned (expiry=%M), "
                     "skipping evict",
                     ip_node->ip_addr, ip_node->block_expiry);
      break; /* 暂停淘汰（避免循环查找） */
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0, "waf_dyn: evicting ip=%uD, score=%uA, last_seen=%M",
                   ip_node->ip_addr, ip_node->score, ip_node->last_seen);

    ngx_queue_remove(&ip_node->queue);
    ngx_rbtree_delete(&ctx->rbtree, &ip_node->node);
    ngx_slab_free_locked(ctx->shpool, ip_node);

    evicted++;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "waf_dyn: evicted %ui nodes", evicted);
  return evicted;
}

/* ===== 红黑树插入回调 ===== */
static void waf_dyn_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
                                        ngx_rbtree_node_t *sentinel)
{
  ngx_rbtree_node_t **p;
  waf_dyn_ip_node_t *node_new, *node_temp;

  for (;;) {
    node_new = (waf_dyn_ip_node_t *)node;
    node_temp = (waf_dyn_ip_node_t *)temp;

    if (node_new->ip_addr < node_temp->ip_addr) {
      p = &temp->left;
    } else if (node_new->ip_addr > node_temp->ip_addr) {
      p = &temp->right;
    } else {
      /* 相同IP：不应该发生（调用前应先查找） */
      return;
    }

    if (*p == sentinel) {
      break;
    }

    temp = *p;
  }

  *p = node;
  node->parent = temp;
  node->left = sentinel;
  node->right = sentinel;

  ngx_rbt_red(node);
}

/* ===== 共享内存初始化回调 ===== */
ngx_int_t waf_dyn_shm_zone_init(ngx_shm_zone_t *shm_zone, void *data)
{
  ngx_slab_pool_t *shpool;
  waf_dyn_shm_ctx_t *ctx;

  shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
  if (shpool == NULL) {
    return NGX_ERROR;
  }

  if (shm_zone->shm.exists) {
    /* 复用旧的上下文（nginx reload） */
    shm_zone->data = shpool->data;
    ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0,
                  "waf_dyn: shm zone \"%V\" already exists, reusing", &shm_zone->shm.name);
    return NGX_OK;
  }

  /* 新建：从 slab 分配上下文并初始化 */
  ctx = ngx_slab_alloc(shpool, sizeof(waf_dyn_shm_ctx_t));
  if (ctx == NULL) {
    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                  "waf_dyn: failed to allocate shm ctx for zone \"%V\"", &shm_zone->shm.name);
    return NGX_ERROR;
  }

  ngx_memzero(ctx, sizeof(waf_dyn_shm_ctx_t));
  ctx->shpool = shpool;

  ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel, waf_dyn_rbtree_insert_value);
  ngx_queue_init(&ctx->lru_queue);

  shpool->data = ctx;
  shm_zone->data = ctx;

  ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0,
                "waf_dyn: initialized new shm zone \"%V\" with rbtree & LRU", &shm_zone->shm.name);

  (void)data; /* 保留参数用于未来扩展 */
  return NGX_OK;
}

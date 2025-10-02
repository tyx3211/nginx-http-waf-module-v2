#include "ngx_http_waf_dynamic_block.h"
#include "ngx_http_waf_log.h"

/*
 * ================================================================
 *  STUB IMPLEMENTATION (M2.5)
 *  动态信誉与共享内存：
 *  - 当前阶段不进行真实执法，也不访问 rbtree/slab
 *  - 仅在请求 ctx 中累计 score，并提供“未封禁”判定
 *  - M5 接入共享内存、窗口、封禁阈值与并发控制
 * ================================================================
 */

void waf_dyn_init_shm_zone(ngx_cycle_t *cycle)
{
  (void)cycle; /* 存根：暂不初始化共享内存结构 */
}

void waf_dyn_score_add(ngx_http_request_t *r, ngx_uint_t delta)
{
  if (r == NULL)
    return;
  /* 存根：无专用 ctx 存取；改为静默 */
  ngx_http_waf_ctx_t *ctx = NULL;
  (void)ctx; /* 占位避免未使用警告 */
  (void)delta;
}

ngx_flag_t waf_dyn_is_banned(ngx_http_request_t *r)
{
  (void)r;
  /* 存根阶段恒返回未封禁 */
  return 0;
}

static void waf_dyn_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                        ngx_rbtree_node_t *node,
                                        ngx_rbtree_node_t *sentinel)
{
  /* 简单按 key 插入，后续可扩展为 hash(ip) 或复合键 */
  ngx_rbtree_node_t **p;

  for (;;) {
    p = (node->key < temp->key) ? &temp->left : &temp->right;

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

ngx_int_t waf_dyn_shm_zone_init(ngx_shm_zone_t *shm_zone, void *data)
{
  ngx_slab_pool_t *shpool;
  waf_dyn_shm_ctx_t *ctx;

  shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
  if (shpool == NULL) {
    return NGX_ERROR;
  }

  if (shm_zone->shm.exists) {
    /* 复用旧的上下文 */
    shm_zone->data = shpool->data;
    return NGX_OK;
  }

  /* 新建：从 slab 分配上下文并初始化 rbtree/queue */
  ctx = ngx_slab_alloc(shpool, sizeof(waf_dyn_shm_ctx_t));
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  ngx_rbtree_init(&ctx->rbtree, &ctx->sentinel, waf_dyn_rbtree_insert_value);
  ngx_queue_init(&ctx->lru_queue);

  shpool->data = ctx;
  shm_zone->data = ctx;

  return NGX_OK;
}

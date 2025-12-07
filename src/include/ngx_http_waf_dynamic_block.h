#ifndef NGX_HTTP_WAF_DYNAMIC_BLOCK_H
#define NGX_HTTP_WAF_DYNAMIC_BLOCK_H

#include <ngx_core.h>
#include <ngx_http.h>

/*
 * ================================================================
 *  动态信誉与共享内存模块（M5）
 *  - 红黑树存储IP节点，LRU队列淘汰
 *  - 评分窗口、封禁阈值、过期检查
 *  - 使用 shpool->mutex 保证并发正确性
 * ================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  ngx_str_t name;  /* shm zone 名称 */
  ngx_uint_t size; /* shm 大小（字节） */
} ngx_http_waf_shm_conf_t;

/* IP节点结构（存储在共享内存中） */
typedef struct {
  ngx_rbtree_node_t node;       /* 红黑树节点（必须是第一个成员） */
  ngx_queue_t queue;            /* LRU队列节点 */
  ngx_uint_t ip_addr;           /* IPv4地址（网络字节序） */
  ngx_atomic_t score;           /* 当前窗口内的风险评分 */
  ngx_msec_t last_seen;         /* 最后访问时间戳（用于LRU） */
  ngx_msec_t window_start_time; /* 当前评分窗口开始时间 */
  ngx_msec_t block_expiry;      /* 封禁过期时间（0表示未封禁） */
} waf_dyn_ip_node_t;

/* 共享内存上下文（位于shm开头） */
typedef struct waf_dyn_shm_ctx_s {
  ngx_rbtree_t rbtree;
  ngx_rbtree_node_t sentinel;
  ngx_queue_t lru_queue;
  ngx_slab_pool_t *shpool; /* 指向slab池的指针 */
} waf_dyn_shm_ctx_t;

/* API：评分与封禁检查 */
void waf_dyn_init_shm_zone(ngx_cycle_t *cycle); /* 生命周期入口（当前为空实现） */

void waf_dyn_score_add(ngx_http_request_t *r, ngx_uint_t delta);
ngx_flag_t waf_dyn_is_banned(ngx_http_request_t *r);
ngx_uint_t waf_dyn_peek_score(ngx_http_request_t *r);

/* 共享内存初始化回调（挂到 ngx_shm_zone_t->init） */
ngx_int_t waf_dyn_shm_zone_init(ngx_shm_zone_t *shm_zone, void *data);

#ifdef __cplusplus
}
#endif

#endif /* NGX_HTTP_WAF_DYNAMIC_BLOCK_H */

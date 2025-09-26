#ifndef NGX_HTTP_WAF_DYNAMIC_BLOCK_H
#define NGX_HTTP_WAF_DYNAMIC_BLOCK_H

#include <ngx_core.h>
#include <ngx_http.h>

/*
 * ================================================================
 *  STUB IMPLEMENTATION (M2.5)
 *  动态信誉与共享内存模块（存根）：
 *  - 暴露稳定 API 与数据结构
 *  - M5 实现评分/衰减/封禁与并发正确性
 * ================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ngx_str_t   name;    /* shm zone 名称 */
    ngx_uint_t  size;    /* shm 大小（字节） */
} ngx_http_waf_shm_conf_t;

/* 评分与封禁 API（存根：不执法） */
void waf_dyn_init_shm_zone(ngx_cycle_t* cycle); /* 存根：声明周期入口，占位 */

void waf_dyn_score_add(ngx_http_request_t* r, ngx_uint_t delta);
ngx_flag_t waf_dyn_is_banned(ngx_http_request_t* r);

/* 共享内存上下文（M2.5：仅初始化结构，不执法） */
typedef struct waf_dyn_shm_ctx_s {
    ngx_rbtree_t         rbtree;
    ngx_rbtree_node_t    sentinel;
    ngx_queue_t          lru_queue;
} waf_dyn_shm_ctx_t;

/* 共享内存初始化回调（挂到 ngx_shm_zone_t->init） */
ngx_int_t waf_dyn_shm_zone_init(ngx_shm_zone_t *shm_zone, void *data);

#ifdef __cplusplus
}
#endif

#endif /* NGX_HTTP_WAF_DYNAMIC_BLOCK_H */










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

void waf_dyn_init_shm_zone(ngx_cycle_t* cycle) {
    (void)cycle; /* 存根：暂不初始化共享内存结构 */
}

void waf_dyn_score_add(ngx_http_request_t* r, ngx_uint_t delta) {
    if (r == NULL) return;
    /* 存根：无专用 ctx 存取；改为静默 */
    ngx_http_waf_ctx_t* ctx = NULL;
    (void)ctx; /* 占位避免未使用警告 */
    (void)delta;
}

ngx_flag_t waf_dyn_is_banned(ngx_http_request_t* r) {
    (void)r;
    /* 存根阶段恒返回未封禁 */
    return 0;
}



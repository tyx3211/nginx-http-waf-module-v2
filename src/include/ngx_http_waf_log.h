#ifndef NGX_HTTP_WAF_LOG_H
#define NGX_HTTP_WAF_LOG_H

#include <ngx_core.h>
#include <ngx_http.h>
#include <yyjson/yyjson.h>
#include "ngx_http_waf_module_v2.h"

/*
 * ================================================================
 *  STUB IMPLEMENTATION (M2.5)
 *  本文件为“日志模块”的存根实现接口声明：
 *  - 仅提供稳定接口与最小请求态聚合字段
 *  - 行为在 M6 中完善（JSONL 文件落盘、级别/完整性策略等）
 *  - 目前的实现只会在 flush 时输出一行 error_log 摘要
 * ================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WAF_LOG_NONE  = 0,
    WAF_LOG_DEBUG = 1,
    WAF_LOG_INFO  = 2,
    WAF_LOG_ERROR = 3
} waf_log_level_e;

typedef struct ngx_http_waf_ctx_s {
    yyjson_mut_doc* log_doc;         /* 存根阶段可为空：不真正构建 JSON 文档 */
    yyjson_mut_val* events;          /* 存根阶段可为空 */
    waf_log_level_e effective_level; /* 本次请求的整体日志级别 */
    ngx_uint_t      total_score;     /* 动态信誉累计分（存根阶段仅内存字段） */
    ngx_uint_t      final_status;    /* 最终 HTTP 状态（若有） */
    ngx_uint_t      final_action;    /* 0=未知 1=BLOCK 2=LOG 3=BYPASS（存根占位语义） */
    unsigned        has_complete_events:1; /* 是否写入过完整性事件 */
} ngx_http_waf_ctx_t;

void waf_log_init_request(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);

/* 完整性接口：一定附加事件并提升 effective_level（存根不真正构建 JSON） */
void waf_log_append_event_complete(ngx_http_request_t* r,
                                   ngx_http_waf_ctx_t* ctx,
                                   waf_log_level_e level);

/* 常规接口：级别不足可跳过；存根阶段默认同 append_event_complete 行为 */
void waf_log_append_event(ngx_http_request_t* r,
                          ngx_http_waf_ctx_t* ctx,
                          waf_log_level_e level);

/* 最终落盘（存根阶段仅 error_log 一行摘要；BLOCK 强制输出） */
void waf_log_flush(ngx_http_request_t* r,
                   ngx_http_waf_main_conf_t* mcf,
                   ngx_http_waf_loc_conf_t* lcf,
                   ngx_http_waf_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* NGX_HTTP_WAF_LOG_H */












#ifndef _NGX_HTTP_WAF_TYPES_H_INCLUDED_
#define _NGX_HTTP_WAF_TYPES_H_INCLUDED_

/* 公共类型定义，避免循环包含。
 * 仅放置轻量的枚举与前置声明。
 */

typedef enum {
    WAF_RC_CONTINUE = 0,   /* 继续后续阶段 */
    WAF_RC_BYPASS,         /* 本模块后续阶段不再执行（外层映射 NGX_DECLINED） */
    WAF_RC_BLOCK,          /* 阻断（外层返回 HTTP_xxx） */
    WAF_RC_ASYNC,          /* 预留：阶段内部进入异步（外层映射 NGX_DONE） */
    WAF_RC_ERROR           /* 内部错误（外层返回 500） */
} waf_rc_e;

typedef enum {
    WAF_FINAL_NONE   = 0,
    WAF_FINAL_BLOCK  = 1,
    WAF_FINAL_BYPASS = 2
} waf_final_action_e;

/* ctx 前置声明（完整定义在 ngx_http_waf_log.h） */
typedef struct ngx_http_waf_ctx_s ngx_http_waf_ctx_t;

#endif /* _NGX_HTTP_WAF_TYPES_H_INCLUDED_ */

#ifndef _NGX_HTTP_WAF_TYPES_H_INCLUDED_
#define _NGX_HTTP_WAF_TYPES_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>

/* 公共枚举与前置声明，供跨模块引用，避免循环包含 */

typedef enum {
    WAF_RC_CONTINUE = 0,
    WAF_RC_BYPASS,
    WAF_RC_BLOCK,
    WAF_RC_ASYNC,
    WAF_RC_ERROR
} waf_rc_e;

typedef enum {
    WAF_FINAL_NONE   = 0,
    WAF_FINAL_BLOCK  = 1,
    WAF_FINAL_BYPASS = 2,
} waf_final_action_e;

/* 前置声明 ctx（实际定义在日志模块头中） */
struct ngx_http_waf_ctx_s;
typedef struct ngx_http_waf_ctx_s ngx_http_waf_ctx_t;

#endif /* _NGX_HTTP_WAF_TYPES_H_INCLUDED_ */



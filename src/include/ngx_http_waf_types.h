/* 统一收敛为单个防重宏定义块，移除重复定义 */
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

typedef enum { WAF_FINAL_NONE = 0,
               WAF_FINAL_BLOCK = 1,
               WAF_FINAL_BYPASS = 2 } waf_final_action_e;

/* 前置声明 ctx（实际定义在日志模块头中） */
struct ngx_http_waf_ctx_s;
typedef struct ngx_http_waf_ctx_s ngx_http_waf_ctx_t;

#endif /* _NGX_HTTP_WAF_TYPES_H_INCLUDED_ */

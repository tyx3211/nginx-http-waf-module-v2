#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/* 本文件不直接使用模块头定义，配置/指令声明移至 ngx_http_waf_config.c */

/* v2 模块骨架：仅保留 ctx、postconfiguration 与外部符号引用 */

/* 外部符号：配置函数与命令表在 ngx_http_waf_config.c 中实现 */
extern void* ngx_http_waf_create_main_conf(ngx_conf_t *cf);
extern char* ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
extern void* ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
extern char* ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
extern ngx_command_t ngx_http_waf_commands[];
extern ngx_module_t ngx_http_waf_module; /* 前置声明，供 ngx_http_get_module_*_conf 使用 */

/* STUB 接口（M2.5）：日志与动作 */
#include "ngx_http_waf_log.h"
#include "ngx_http_waf_action.h"

static ngx_int_t ngx_http_waf_access_handler(ngx_http_request_t *r)
{
    /* STUB: 初始化请求态 ctx 并进行一次最小动作与日志调用 */
    ngx_http_waf_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    waf_log_init_request(r, ctx);

    /* 示例：对 GET/HEAD 不拦截，仅记录 DEBUG 事件；其他方法示例触发 BYPASS 或 BLOCK */
    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
        waf_log_append_event(r, ctx, WAF_LOG_DEBUG);
        ctx->final_action = 3; /* BYPASS 占位 */
        ctx->final_status = 0;
        /* 尾部统一 FINAL flush（ALLOW），具备去重保护 */
        ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
        ngx_http_waf_loc_conf_t*  lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        waf_log_flush_final(r, mcf, lcf, ctx, "ALLOW");
        return NGX_DECLINED;
    }

    /* 非 GET/HEAD：演示调用统一动作（intent=LOG，score_delta=0） */
    waf_enforce(r, ngx_http_get_module_main_conf(r, ngx_http_waf_module),
                      ngx_http_get_module_loc_conf(r, ngx_http_waf_module),
                      ctx, WAF_INTENT_LOG, 0, 0, 0);

    /* 尾部统一 FINAL flush（ALLOW），若前面已 BLOCK/BYPASS，将被去重 */
    {
        ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
        ngx_http_waf_loc_conf_t*  lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        waf_log_flush_final(r, mcf, lcf, ctx, "ALLOW");
    }
    return NGX_DECLINED;
}

static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf)
{
    /* 注册 ACCESS 阶段处理函数（优先级靠前） */
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_access_handler;

    return NGX_OK;
}

static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_waf_postconfiguration,     /* postconfiguration */
    ngx_http_waf_create_main_conf,      /* create main conf */
    ngx_http_waf_init_main_conf,        /* init main conf */
    NULL,                               /* create srv conf */
    NULL,                               /* merge srv conf */
    ngx_http_waf_create_loc_conf,       /* create loc conf */
    ngx_http_waf_merge_loc_conf         /* merge loc conf */
};

ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,           /* module context */
    ngx_http_waf_commands,              /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

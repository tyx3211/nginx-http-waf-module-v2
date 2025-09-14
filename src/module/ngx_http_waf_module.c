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

static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf)
{
    /* STUB: no handlers registered yet */
    (void)cf;
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

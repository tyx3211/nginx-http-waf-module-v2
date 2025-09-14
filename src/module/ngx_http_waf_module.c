#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* STUB: Minimal v2 module skeleton for tooling and compile_commands.json generation. */
#define WAF_STUB 1

static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf)
{
    /* STUB: no handlers registered yet */
    (void)cf;
    return NGX_OK;
}

static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_waf_postconfiguration,     /* postconfiguration */
    NULL,                               /* create main conf */
    NULL,                               /* init main conf */
    NULL,                               /* create srv conf */
    NULL,                               /* merge srv conf */
    NULL,                               /* create loc conf */
    NULL                                /* merge loc conf */
};

ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,           /* module context */
    NULL,                               /* module directives */
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



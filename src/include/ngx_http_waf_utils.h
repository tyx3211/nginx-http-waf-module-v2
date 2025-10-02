#ifndef NGX_HTTP_WAF_UTILS_H
#define NGX_HTTP_WAF_UTILS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>

/* 匹配与解析工具函数声明 */

/* 大小写可选的子串查找（needle 为空串视为命中） */
ngx_uint_t ngx_http_waf_contains_ci(const ngx_str_t *hay,
                                    const ngx_str_t *needle,
                                    ngx_flag_t caseless);

/* REGEX 列表任意命中 */
ngx_uint_t ngx_http_waf_regex_any_match(ngx_array_t *regexes,
                                        const ngx_str_t *subject);

/* 获取请求头首个命中的值（名称大小写不敏感），命中返回1并写入 out */
ngx_uint_t ngx_http_waf_get_header(ngx_http_request_t *r, const ngx_str_t *name,
                                   ngx_str_t *out);

/* 遍历 query args，按 name 或 value 匹配 contains/regex */
ngx_uint_t
ngx_http_waf_args_iter_match(const ngx_str_t *args, ngx_flag_t match_name,
                             ngx_flag_t caseless, ngx_array_t *patterns,
                             ngx_array_t *regexes, ngx_flag_t is_regex);

/* 其他工具 */
void ngx_http_waf_trim(ngx_str_t *s);

#endif /* NGX_HTTP_WAF_UTILS_H */

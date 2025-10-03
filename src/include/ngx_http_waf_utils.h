/*
 * ================================================================
 *  WAF工具函数库（M5增强）
 *  - 客户端IP获取（支持X-Forwarded-For）
 *  - IP地址格式转换（主机字节序、点分十进制）
 * ================================================================
 */

#ifndef NGX_HTTP_WAF_UTILS_H
#define NGX_HTTP_WAF_UTILS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * 获取客户端IP地址（主机字节序的uint32_t）
 *
 * 行为：
 *  - 若waf_trust_xff=on且存在X-Forwarded-For头，解析最左侧IP
 *  - 否则使用TCP连接的sockaddr
 *  - 仅支持IPv4，IPv6返回0
 *
 * 返回：
 *  - 成功：主机字节序的32位IP（如192.168.1.1 → 0xC0A80101）
 *  - 失败：0（无效IP或IPv6）
 */
ngx_uint_t waf_utils_get_client_ip(ngx_http_request_t *r, ngx_flag_t trust_xff);

/*
 * 将uint32_t IP（主机字节序）转换为点分十进制字符串
 *
 * 参数：
 *  - ip: 主机字节序的IP（0xC0A80101）
 *  - pool: 内存池（用于分配ngx_str_t.data）
 *
 * 返回：
 *  - ngx_str_t: 分配的字符串（如"192.168.1.1"）
 *  - 失败时len=0
 *
 * 示例：
 *  ngx_str_t ip_str = waf_utils_ip_to_str(0xC0A80101, r->pool);
 *  // ip_str = "192.168.1.1"
 */
ngx_str_t waf_utils_ip_to_str(ngx_uint_t ip, ngx_pool_t *pool);

/*
 * 解析点分十进制字符串为uint32_t IP（主机字节序）
 *
 * 参数：
 *  - ip_str: IP字符串（如"192.168.1.1"）
 *
 * 返回：
 *  - 成功：主机字节序IP
 *  - 失败：0
 *
 * 注意：
 *  - 用于解析X-Forwarded-For中的IP
 *  - 使用nginx的ngx_inet_addr()函数（返回网络字节序，需ntohl转换）
 */
ngx_uint_t waf_utils_parse_ip_str(ngx_str_t *ip_str);

/*
 * ================================================================
 *  字符串处理工具
 * ================================================================
 */

/* 去除首尾空白（原地修改） */
void ngx_http_waf_trim(ngx_str_t *s);

/* 大小写可选的子串查找（contains） */
ngx_uint_t ngx_http_waf_contains_ci(const ngx_str_t *hay, const ngx_str_t *needle,
                                    ngx_flag_t caseless);

/* 大小写可选的全等比较 */
ngx_uint_t ngx_http_waf_equals_ci(const ngx_str_t *a, const ngx_str_t *b, ngx_flag_t caseless);

/*
 * ================================================================
 *  请求数据提取工具
 * ================================================================
 */

/* 获取解码后的完整 query 字符串（使用 r->pool 分配） */
ngx_int_t ngx_http_waf_get_decoded_args_combined(ngx_http_request_t *r, ngx_str_t *out);

/* 收集请求体为连续内存（支持内存缓冲与临时文件） */
ngx_int_t ngx_http_waf_collect_request_body(ngx_http_request_t *r, ngx_str_t *body_str);

/* 对 application/x-www-form-urlencoded 进行 URL 解码 */
ngx_int_t ngx_http_waf_decode_form_urlencoded(ngx_pool_t *pool, const ngx_str_t *in,
                                              ngx_str_t *out);

/* 获取指定请求头的值 */
ngx_uint_t ngx_http_waf_get_header(ngx_http_request_t *r, const ngx_str_t *name, ngx_str_t *out);

/*
 * ================================================================
 *  参数遍历与匹配工具
 * ================================================================
 */

/* 遍历 query args，按 name/value 精确匹配（大小写可选） */
ngx_uint_t ngx_http_waf_args_iter_exact(const ngx_str_t *args, ngx_flag_t match_name,
                                        ngx_flag_t caseless, ngx_array_t *patterns);

/* 遍历 query args 进行模式匹配（contains/regex） */
ngx_uint_t ngx_http_waf_args_iter_match(const ngx_str_t *args, ngx_flag_t match_name,
                                        ngx_flag_t caseless, ngx_array_t *patterns,
                                        ngx_array_t *regexes, ngx_flag_t is_regex);

/*
 * ================================================================
 *  正则匹配工具
 * ================================================================
 */

/* REGEX 任意命中（数组中任一正则匹配即返回1） */
ngx_uint_t ngx_http_waf_regex_any_match(ngx_array_t *regexes, const ngx_str_t *subject);

#endif /* NGX_HTTP_WAF_UTILS_H */

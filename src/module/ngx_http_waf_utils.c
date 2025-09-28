#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include "ngx_http_waf_utils.h"

/*
 * 通用工具函数（骨架）
 * - 当前仅保留可编译的最小实现
 */

/* 去除首尾空白（原地） */
void ngx_http_waf_trim(ngx_str_t* s) {
    if (s == NULL || s->data == NULL || s->len == 0) return;
    u_char* start = s->data;
    u_char* end = s->data + s->len - 1;
    while (start <= end && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')) start++;
    while (end >= start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    size_t new_len = (size_t)(end >= start ? (end - start + 1) : 0);
    if (start != s->data && new_len > 0) {
        ngx_memmove(s->data, start, new_len);
    }
    s->len = new_len;
    if (s->data) s->data[new_len] = '\0';
}

/* 大小写可选子串查找 */
ngx_uint_t ngx_http_waf_contains_ci(const ngx_str_t* hay,
                                    const ngx_str_t* needle,
                                    ngx_flag_t caseless) {
    if (hay == NULL || needle == NULL || hay->data == NULL || needle->data == NULL) return 0;
    if (needle->len == 0) return 1;
    if (hay->len < needle->len) return 0;
    const u_char* h = hay->data;
    const u_char* n = needle->data;
    size_t hl = hay->len;
    size_t nl = needle->len;
    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        for (; j < nl; j++) {
            u_char hc = h[i + j];
            u_char nc = n[j];
            if (caseless) {
                if (ngx_tolower(hc) != ngx_tolower(nc)) break;
            } else {
                if (hc != nc) break;
            }
        }
        if (j == nl) return 1;
    }
    return 0;
}

/* REGEX 任意命中 */
ngx_uint_t ngx_http_waf_regex_any_match(ngx_array_t* regexes,
                                        const ngx_str_t* subject) {
    if (regexes == NULL || subject == NULL || subject->data == NULL) return 0;
    if (subject->len == 0) return 0;
    ngx_regex_t** regs = regexes->elts;
    for (ngx_uint_t i = 0; i < regexes->nelts; i++) {
        if (regs[i] == NULL) continue;
        if (ngx_regex_exec(regs[i], (ngx_str_t*)subject, NULL, 0) >= 0) {
            return 1;
        }
    }
    return 0;
}

/* 获取请求头 */
ngx_uint_t ngx_http_waf_get_header(ngx_http_request_t* r,
                                   const ngx_str_t* name,
                                   ngx_str_t* out) {
    if (r == NULL || name == NULL || out == NULL || name->len == 0) return 0;
    ngx_list_part_t* part = &r->headers_in.headers.part;
    ngx_table_elt_t* h = part->elts;
    for (ngx_uint_t i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].key.len == name->len && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0) {
            *out = h[i].value;
            return 1;
        }
    }
    return 0;
}

/* 遍历 query args 进行匹配 */
ngx_uint_t ngx_http_waf_args_iter_match(const ngx_str_t* args,
                                        ngx_flag_t match_name,
                                        ngx_flag_t caseless,
                                        ngx_array_t* patterns,
                                        ngx_array_t* regexes,
                                        ngx_flag_t is_regex) {
    if (args == NULL || args->data == NULL || args->len == 0) return 0;
    const u_char* p = args->data;
    const u_char* end = args->data + args->len;
    while (p < end) {
        const u_char* name_start = p;
        const u_char* name_end = p;
        const u_char* value_start = NULL;
        const u_char* value_end = NULL;

        while (name_end < end && *name_end != '=' && *name_end != '&') name_end++;
        if (name_end < end && *name_end == '=') {
            value_start = name_end + 1;
            const u_char* q = value_start;
            while (q < end && *q != '&') q++;
            value_end = q;
            p = (q < end ? q + 1 : q);
        } else {
            p = (name_end < end && *name_end == '&') ? name_end + 1 : name_end;
        }

        ngx_str_t name_field;
        name_field.len = (size_t)(name_end - name_start);
        name_field.data = (u_char*)name_start;

        ngx_str_t value_field;
        value_field.len = (size_t)((value_end && value_start) ? (value_end - value_start) : 0);
        value_field.data = (u_char*)(value_start ? value_start : NULL);

        const ngx_str_t* subject = match_name ? &name_field : &value_field;
        if (subject->data == NULL) continue;

        if (is_regex) {
            if (ngx_http_waf_regex_any_match(regexes, subject)) return 1;
        } else if (patterns) {
            ngx_str_t* pats = patterns->elts;
            for (ngx_uint_t i = 0; i < patterns->nelts; i++) {
                if (ngx_http_waf_contains_ci(subject, &pats[i], caseless)) return 1;
            }
        }
    }
    return 0;
}



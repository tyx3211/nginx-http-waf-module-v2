#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

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



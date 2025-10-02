#include "ngx_http_waf_utils.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>

/*
 * 通用工具函数（骨架）
 * - 当前仅保留可编译的最小实现
 */

/* 本地工具实现（静态）在文件后部给出原型+实现 */
static ngx_int_t ngx_http_waf_plus_to_space_and_unescape(ngx_pool_t *pool,
                                                         const ngx_str_t *in,
                                                         ngx_str_t *out);

/* 去除首尾空白（原地） */
void ngx_http_waf_trim(ngx_str_t *s)
{
  if (s == NULL || s->data == NULL || s->len == 0)
    return;
  u_char *start = s->data;
  u_char *end = s->data + s->len - 1;
  while (start <= end &&
         (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r'))
    start++;
  while (end >= start &&
         (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
    end--;
  size_t new_len = (size_t)(end >= start ? (end - start + 1) : 0);
  if (start != s->data && new_len > 0) {
    ngx_memmove(s->data, start, new_len);
  }
  s->len = new_len;
  if (s->data)
    s->data[new_len] = '\0';
}

/* 大小写可选子串查找 */
ngx_uint_t ngx_http_waf_contains_ci(const ngx_str_t *hay,
                                    const ngx_str_t *needle,
                                    ngx_flag_t caseless)
{
  if (hay == NULL || needle == NULL || hay->data == NULL ||
      needle->data == NULL)
    return 0;
  if (needle->len == 0)
    return 1;
  if (hay->len < needle->len)
    return 0;
  const u_char *h = hay->data;
  const u_char *n = needle->data;
  size_t hl = hay->len;
  size_t nl = needle->len;
  for (size_t i = 0; i + nl <= hl; i++) {
    size_t j = 0;
    for (; j < nl; j++) {
      u_char hc = h[i + j];
      u_char nc = n[j];
      if (caseless) {
        if (ngx_tolower(hc) != ngx_tolower(nc))
          break;
      } else {
        if (hc != nc)
          break;
      }
    }
    if (j == nl)
      return 1;
  }
  return 0;
}

/* 统一解码后的完整 query 字符串视图（使用 r->pool 分配） */
ngx_int_t ngx_http_waf_get_decoded_args_combined(ngx_http_request_t *r,
                                                 ngx_str_t *out)
{
  if (r == NULL || out == NULL)
    return NGX_ERROR;
  return ngx_http_waf_plus_to_space_and_unescape(r->pool, &r->args, out);
}

/* 收集请求体为连续内存（支持内存缓冲与临时文件，NUL 结尾） */
ngx_int_t ngx_http_waf_collect_request_body(ngx_http_request_t *r,
                                            ngx_str_t *body_str)
{
  if (r == NULL || body_str == NULL)
    return NGX_ERROR;
  if (r->request_body == NULL || r->request_body->bufs == NULL)
    return NGX_ERROR;

  ngx_chain_t *cl = r->request_body->bufs;
  size_t total = 0;
  for (ngx_chain_t *c = cl; c != NULL; c = c->next) {
    if (c->buf == NULL)
      continue;
    if (ngx_buf_in_memory(c->buf)) {
      if (c->buf->last > c->buf->pos)
        total += (size_t)(c->buf->last - c->buf->pos);
    } else if (c->buf->in_file) {
      if (c->buf->file_last > c->buf->file_pos)
        total += (size_t)(c->buf->file_last - c->buf->file_pos);
    }
  }

  u_char *dst = ngx_pnalloc(r->pool, total + 1);
  if (dst == NULL)
    return NGX_ERROR;

  u_char *p = dst;
  for (ngx_chain_t *c = cl; c != NULL; c = c->next) {
    if (c->buf == NULL)
      continue;
    if (ngx_buf_in_memory(c->buf)) {
      size_t sz = (size_t)(c->buf->last - c->buf->pos);
      if (sz > 0) {
        ngx_memcpy(p, c->buf->pos, sz);
        p += sz;
      }
    } else if (c->buf->in_file) {
      size_t sz = (size_t)(c->buf->file_last - c->buf->file_pos);
      if (sz > 0) {
        if (r->request_body->temp_file == NULL) {
          return NGX_ERROR;
        }
        ssize_t n = ngx_read_file(&r->request_body->temp_file->file, p, sz,
                                  c->buf->file_pos);
        if (n < 0 || (size_t)n != sz) {
          return NGX_ERROR;
        }
        p += (size_t)n;
      }
    }
  }

  *p = '\0';
  body_str->data = dst;
  body_str->len = (size_t)(p - dst);
  return NGX_OK;
}

/* 对 application/x-www-form-urlencoded 的 URL 解码（+ 转空格） */
ngx_int_t ngx_http_waf_decode_form_urlencoded(ngx_pool_t *pool,
                                              const ngx_str_t *in,
                                              ngx_str_t *out)
{
  return ngx_http_waf_plus_to_space_and_unescape(pool, in, out);
}

/* 大小写可选的全等比较（等长逐字节） */
ngx_uint_t ngx_http_waf_equals_ci(const ngx_str_t *a, const ngx_str_t *b,
                                  ngx_flag_t caseless)
{
  if (a == NULL || b == NULL || a->data == NULL || b->data == NULL)
    return 0;
  if (a->len != b->len)
    return 0;
  const u_char *pa = a->data;
  const u_char *pb = b->data;
  for (size_t i = 0; i < a->len; i++) {
    u_char ca = pa[i];
    u_char cb = pb[i];
    if (caseless) {
      if (ngx_tolower(ca) != ngx_tolower(cb))
        return 0;
    } else {
      if (ca != cb)
        return 0;
    }
  }
  return 1;
}

/* 将 '+' 转为空格并进行一次 URL 解码（%XX） */
static ngx_int_t ngx_http_waf_plus_to_space_and_unescape(ngx_pool_t *pool,
                                                         const ngx_str_t *in,
                                                         ngx_str_t *out)
{
  if (in == NULL || out == NULL) {
    return NGX_ERROR;
  }
  if (in->len == 0 || in->data == NULL) {
    out->data = (u_char *)"";
    out->len = 0;
    return NGX_OK;
  }
  u_char *tmp = ngx_pnalloc(pool, in->len);
  if (tmp == NULL)
    return NGX_ERROR;
  for (size_t i = 0; i < in->len; i++) {
    tmp[i] = (in->data[i] == '+') ? ' ' : in->data[i];
  }
  u_char *dst = ngx_pnalloc(pool, in->len + 1);
  if (dst == NULL)
    return NGX_ERROR;
  u_char *dst_ptr = dst;
  u_char *src_ptr = tmp;
  ngx_unescape_uri(&dst_ptr, &src_ptr, in->len, 0);
  out->data = dst;
  out->len = (size_t)(dst_ptr - dst);
  out->data[out->len] = '\0';
  return NGX_OK;
}

/* 遍历 query args，按 name/value 精确匹配（大小写可选） */
ngx_uint_t ngx_http_waf_args_iter_exact(const ngx_str_t *args,
                                        ngx_flag_t match_name,
                                        ngx_flag_t caseless,
                                        ngx_array_t *patterns)
{
  if (args == NULL || args->data == NULL || args->len == 0 || patterns == NULL)
    return 0;
  const u_char *p = args->data;
  const u_char *end = args->data + args->len;
  while (p < end) {
    const u_char *name_start = p;
    const u_char *name_end = p;
    const u_char *value_start = NULL;
    const u_char *value_end = NULL;

    while (name_end < end && *name_end != '=' && *name_end != '&')
      name_end++;
    if (name_end < end && *name_end == '=') {
      value_start = name_end + 1;
      const u_char *q = value_start;
      while (q < end && *q != '&')
        q++;
      value_end = q;
      p = (q < end ? q + 1 : q);
    } else {
      p = (name_end < end && *name_end == '&') ? name_end + 1 : name_end;
    }

    ngx_str_t raw;
    raw.len = match_name ? (size_t)(name_end - name_start)
                         : (size_t)((value_end && value_start)
                                        ? (value_end - value_start)
                                        : 0);
    raw.data = (u_char *)(match_name ? name_start : (value_start ? value_start : NULL));
    if (raw.data == NULL)
      continue;

    ngx_str_t decoded;
    if (ngx_http_waf_plus_to_space_and_unescape(ngx_cycle->pool, &raw,
                                                &decoded) != NGX_OK) {
      continue;
    }

    ngx_str_t *pats = patterns->elts;
    for (ngx_uint_t i = 0; i < patterns->nelts; i++) {
      if (ngx_http_waf_equals_ci(&decoded, &pats[i], caseless)) {
        return 1;
      }
    }
  }
  return 0;
}

/* REGEX 任意命中 */
ngx_uint_t ngx_http_waf_regex_any_match(ngx_array_t *regexes,
                                        const ngx_str_t *subject)
{
  if (regexes == NULL || subject == NULL || subject->data == NULL)
    return 0;
  if (subject->len == 0)
    return 0;
  ngx_regex_t **regs = regexes->elts;
  for (ngx_uint_t i = 0; i < regexes->nelts; i++) {
    if (regs[i] == NULL)
      continue;
    if (ngx_regex_exec(regs[i], (ngx_str_t *)subject, NULL, 0) >= 0) {
      return 1;
    }
  }
  return 0;
}

/* 获取请求头 */
ngx_uint_t ngx_http_waf_get_header(ngx_http_request_t *r, const ngx_str_t *name,
                                   ngx_str_t *out)
{
  if (r == NULL || name == NULL || out == NULL || name->len == 0)
    return 0;
  ngx_list_part_t *part = &r->headers_in.headers.part;
  ngx_table_elt_t *h = part->elts;
  for (ngx_uint_t i = 0;; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL)
        break;
      part = part->next;
      h = part->elts;
      i = 0;
    }
    if (h[i].key.len == name->len &&
        ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0) {
      *out = h[i].value;
      return 1;
    }
  }
  return 0;
}

/* 遍历 query args 进行匹配 */
ngx_uint_t
ngx_http_waf_args_iter_match(const ngx_str_t *args, ngx_flag_t match_name,
                             ngx_flag_t caseless, ngx_array_t *patterns,
                             ngx_array_t *regexes, ngx_flag_t is_regex)
{
  if (args == NULL || args->data == NULL || args->len == 0)
    return 0;
  const u_char *p = args->data;
  const u_char *end = args->data + args->len;
  while (p < end) {
    const u_char *name_start = p;
    const u_char *name_end = p;
    const u_char *value_start = NULL;
    const u_char *value_end = NULL;

    while (name_end < end && *name_end != '=' && *name_end != '&')
      name_end++;
    if (name_end < end && *name_end == '=') {
      value_start = name_end + 1;
      const u_char *q = value_start;
      while (q < end && *q != '&')
        q++;
      value_end = q;
      p = (q < end ? q + 1 : q);
    } else {
      p = (name_end < end && *name_end == '&') ? name_end + 1 : name_end;
    }

    /* 解码 subject（一次性 +→空格 与 %XX） */
    ngx_str_t raw;
    raw.len = match_name ? (size_t)(name_end - name_start)
                         : (size_t)((value_end && value_start)
                                        ? (value_end - value_start)
                                        : 0);
    raw.data = (u_char *)(match_name ? name_start : (value_start ? value_start : NULL));
    if (raw.data == NULL)
      continue;
    ngx_str_t decoded;
    if (ngx_http_waf_plus_to_space_and_unescape(ngx_cycle->pool, &raw,
                                                &decoded) != NGX_OK) {
      continue;
    }

    if (is_regex) {
      if (ngx_http_waf_regex_any_match(regexes, &decoded))
        return 1;
    } else if (patterns) {
      ngx_str_t *pats = patterns->elts;
      for (ngx_uint_t i = 0; i < patterns->nelts; i++) {
        if (ngx_http_waf_contains_ci(&decoded, &pats[i], caseless))
          return 1;
      }
    }
  }
  return 0;
}

#include "ngx_http_waf_module_v2.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <yyjson/yyjson.h>

#include <stdarg.h>
#include <uthash/uthash.h>

/*
 * JSON 解析与合并实现（符合 waf-json-spec-v2.0-simplified）
 * - 支持 meta.extends 字符串与对象语法
 * - imported_set 禁用/重写与 duplicatePolicy
 * - target 归一化、ALL_PARAMS 展开、HEADER 约束
 * - 错误定位：文件路径 + JSON Pointer + 中文描述
 */

#define WAF_JSON_MSG_BUF 512

/* 枚举：重复策略 */
typedef enum {
  WAF_DUP_POLICY_WARN_SKIP = 0,
  WAF_DUP_POLICY_WARN_KEEP_LAST = 1,
  WAF_DUP_POLICY_ERROR = 2
} waf_dup_policy_e;

/* 枚举：目标字段 */
typedef enum {
  WAF_TARGET_CLIENT_IP = 0,
  WAF_TARGET_URI,
  WAF_TARGET_ALL_PARAMS, /* 仅解析过程使用 */
  WAF_TARGET_ARGS_COMBINED,
  WAF_TARGET_ARGS_NAME,
  WAF_TARGET_ARGS_VALUE,
  WAF_TARGET_BODY,
  WAF_TARGET_HEADER,
  WAF_TARGET_ALL_TARGETS
} waf_target_e;

typedef struct {
  ngx_uint_t count;
  ngx_uint_t has_header;
  waf_target_e items[WAF_TARGET_ALL_TARGETS];
} waf_target_list_t;

typedef struct {
  int64_t id;
  yyjson_mut_val *rule;
  ngx_str_t file;
  ngx_str_t pointer;
} waf_rule_entry_t;

typedef struct {
  ngx_str_t tag;
  ngx_str_t pointer;
  waf_target_list_t targets;
} waf_rewrite_tag_rule_t;

typedef struct {
  ngx_array_t *ids; /* 元素类型：int64_t */
  ngx_str_t pointer;
  waf_target_list_t targets;
} waf_rewrite_ids_rule_t;

typedef struct {
  ngx_array_t *tag_rules; /* waf_rewrite_tag_rule_t */
  ngx_array_t *id_rules;  /* waf_rewrite_ids_rule_t */
} waf_rewrite_plan_t;

typedef struct {
  ngx_pool_t *pool;
  ngx_log_t *log;
  ngx_http_waf_json_error_t *err;
  ngx_uint_t max_depth;
  ngx_array_t *stack; /* 环检测：元素类型 ngx_str_t */
  ngx_str_t jsons_root;
  yyjson_mut_doc *out_doc;
} waf_merge_ctx_t;

/* ------------------------ 工具函数 ------------------------ */

/*
 * 函数: waf_json_reset_error
 * 作用: 重置解析错误对象, 清空 file/json_pointer/message, 便于复用
 */

static void waf_json_reset_error(ngx_http_waf_json_error_t *err)
{
  if (err == NULL) {
    return;
  }
  err->file.len = 0;
  err->file.data = NULL;
  err->json_pointer.len = 0;
  err->json_pointer.data = NULL;
  err->message.len = 0;
  err->message.data = NULL;
}

/*
 * 函数: waf_json_set_error
 * 作用: 设置错误对象内容，支持 printf 风格格式化；不直接写日志
 * 说明: 所有字符串内存均从 ctx->pool 分配，以与 Nginx 生命周期对齐
 */
static ngx_int_t waf_json_set_error(waf_merge_ctx_t *ctx, const ngx_str_t *file,
                                    const char *json_pointer, const char *fmt, ...)
{
  if (ctx == NULL || ctx->err == NULL) {
    return NGX_ERROR;
  }

  ngx_http_waf_json_error_t *err = ctx->err;
  /* 记录错误来源文件，便于定位 */
  if (file && file->data) {
    err->file = *file;
  }

  /* 拷贝 JSON Pointer（若提供） */
  if (json_pointer) {
    size_t plen = ngx_strlen(json_pointer);
    u_char *p = ngx_pnalloc(ctx->pool, plen + 1);
    if (p) {
      ngx_memcpy(p, json_pointer, plen);
      p[plen] = '\0';
      err->json_pointer.len = plen;
      err->json_pointer.data = p;
    }
  }

  /* 生成格式化后的错误消息 */
  u_char *buf = ngx_pnalloc(ctx->pool, WAF_JSON_MSG_BUF);
  if (buf) {
    va_list args;
    va_start(args, fmt);
    u_char *end = ngx_vslprintf(buf, buf + WAF_JSON_MSG_BUF, fmt, args);
    va_end(args);
    if (end == NULL) {
      err->message.len = 0;
      err->message.data = NULL;
    } else {
      err->message.len = end - buf;
      err->message.data = buf;
    }
  }

  return NGX_ERROR;
}

/*
 * 函数: waf_str_copy
 * 作用: 将 ngx_str_t 深拷贝到新内存（来自 pool）
 */
static ngx_int_t waf_str_copy(ngx_pool_t *pool, const ngx_str_t *src, ngx_str_t *dst)
{
  if (pool == NULL || src == NULL || dst == NULL) {
    return NGX_ERROR;
  }
  if (src->len == 0) {
    dst->len = 0;
    dst->data = NULL;
    return NGX_OK;
  }
  u_char *p = ngx_pnalloc(pool, src->len);
  if (p == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(p, src->data, src->len);
  dst->data = p;
  dst->len = src->len;
  return NGX_OK;
}

/*
 * 函数: waf_pointer_concat
 * 作用: 连接 JSON Pointer/路径的前后缀，返回新内存
 */
static ngx_int_t waf_pointer_concat(ngx_pool_t *pool, const char *base, const char *suffix,
                                    ngx_str_t *out)
{
  size_t bl = base ? ngx_strlen(base) : 0;
  size_t sl = suffix ? ngx_strlen(suffix) : 0;
  size_t len = bl + sl;
  u_char *p = ngx_pnalloc(pool, len + 1);
  if (p == NULL) {
    return NGX_ERROR;
  }
  if (bl)
    ngx_memcpy(p, base, bl);
  if (sl)
    ngx_memcpy(p + bl, suffix, sl);
  p[len] = '\0';
  out->data = p;
  out->len = len;
  return NGX_OK;
}

/*
 * 函数: ngx_http_waf_str_eq
 * 作用: 判断两个 ngx_str_t 是否完全相等
 */
static ngx_int_t ngx_http_waf_str_eq(const ngx_str_t *a, const ngx_str_t *b)
{
  if (a == NULL || b == NULL) {
    return 0;
  }
  if (a->len != b->len) {
    return 0;
  }
  if (a->len == 0) {
    return 1;
  }
  return ngx_strncmp(a->data, b->data, a->len) == 0;
}

/*
 * 函数: ngx_http_waf_push_path
 * 作用: 将路径压入栈（用于 extends 环检测）
 */
static ngx_int_t ngx_http_waf_push_path(ngx_array_t *stack, const ngx_str_t *path)
{
  ngx_str_t *slot = ngx_array_push(stack);
  if (slot == NULL) {
    return NGX_ERROR;
  }
  *slot = *path;
  return NGX_OK;
}

/*
 * 函数: ngx_http_waf_path_in_stack
 * 作用: 判断路径是否已在栈中（用于检测循环引用）
 */
static ngx_uint_t ngx_http_waf_path_in_stack(ngx_array_t *stack, const ngx_str_t *path)
{
  if (stack == NULL || path == NULL) {
    return 0;
  }
  ngx_str_t *items = stack->elts;
  for (ngx_uint_t i = 0; i < stack->nelts; i++) {
    if (ngx_http_waf_str_eq(&items[i], path)) {
      return 1;
    }
  }
  return 0;
}

/* ------------------------ 路径处理 ------------------------ */

/*
 * 函数: ngx_http_waf_normalize_path
 * 作用: 规范化路径，折叠重复分隔符与 '/./'，并移除尾部多余 '/'
 */
static ngx_int_t ngx_http_waf_normalize_path(ngx_pool_t *pool, ngx_str_t *path)
{
  if (pool == NULL || path == NULL || path->data == NULL || path->len == 0) {
    return NGX_OK;
  }

  u_char *src = path->data;
  size_t n = path->len;
  u_char *dst = ngx_pnalloc(pool, n + 1);
  if (dst == NULL) {
    return NGX_ERROR;
  }

  size_t i = 0, di = 0;
  /* 单次线性扫描，折叠 '//' 与 '/./' 片段 */
  while (i < n) {
    if (src[i] == '/') {
      if (di == 0 || dst[di - 1] != '/') {
        dst[di++] = '/';
      }
      i++;
      if (i < n && src[i] == '.') {
        if (i + 1 == n) {
          i++;
          continue;
        }
        if (src[i + 1] == '/') {
          i += 2;
          continue;
        }
      }
    } else {
      do {
        dst[di++] = src[i++];
      } while (i < n && src[i] != '/');
    }
  }

  /* 去除末尾多余的 '/' */
  if (di > 1 && dst[di - 1] == '/') {
    di--;
  }
  dst[di] = '\0';
  path->data = dst;
  path->len = di;
  return NGX_OK;
}

/*
 * 函数: ngx_http_waf_dirname
 * 作用: 取路径的上级目录（结果已规范化）
 */
ngx_int_t ngx_http_waf_dirname(ngx_pool_t *pool, const ngx_str_t *path, ngx_str_t *out_dir)
{
  if (pool == NULL || path == NULL || out_dir == NULL || path->len == 0) {
    return NGX_ERROR;
  }

  size_t i = path->len;
  while (i > 0) {
    if (path->data[i - 1] == '/') {
      break;
    }
    i--;
  }

  /* 无分隔符时，返回当前目录 '.' */
  if (i == 0) {
    out_dir->len = 1;
    out_dir->data = ngx_pnalloc(pool, 2);
    if (out_dir->data == NULL)
      return NGX_ERROR;
    out_dir->data[0] = '.';
    out_dir->data[1] = '\0';
    return NGX_OK;
  }

  /* 根目录的父目录仍为 '/' */
  if (i == 1 && path->data[0] == '/') {
    out_dir->len = 1;
    out_dir->data = ngx_pnalloc(pool, 2);
    if (out_dir->data == NULL)
      return NGX_ERROR;
    out_dir->data[0] = '/';
    out_dir->data[1] = '\0';
    return NGX_OK;
  }

  out_dir->len = i - 1;
  out_dir->data = ngx_pnalloc(pool, out_dir->len + 1);
  if (out_dir->data == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(out_dir->data, path->data, out_dir->len);
  out_dir->data[out_dir->len] = '\0';

  if (ngx_http_waf_normalize_path(pool, out_dir) != NGX_OK) {
    return NGX_ERROR;
  }
  return NGX_OK;
}

/*
 * 函数: ngx_http_waf_join_path_internal
 * 作用: 将相对路径拼接到 base_dir，若 path 为绝对路径则直接复制
 */
static ngx_int_t ngx_http_waf_join_path_internal(ngx_pool_t *pool, const ngx_str_t *base_dir,
                                                 const ngx_str_t *path, ngx_str_t *out)
{
  if (pool == NULL || path == NULL || out == NULL) {
    return NGX_ERROR;
  }

  if (path->len > 0 && path->data[0] == '/') {
    return waf_str_copy(pool, path, out);
  }

  if (base_dir == NULL || base_dir->len == 0) {
    return waf_str_copy(pool, path, out);
  }

  size_t need_sep = (base_dir->data[base_dir->len - 1] == '/') ? 0 : 1;
  size_t len = base_dir->len + need_sep + path->len;
  u_char *p = ngx_pnalloc(pool, len + 1);
  if (p == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(p, base_dir->data, base_dir->len);
  size_t off = base_dir->len;
  if (need_sep) {
    p[off++] = '/';
  }
  if (path->len) {
    ngx_memcpy(p + off, path->data, path->len);
  }
  p[len] = '\0';
  out->data = p;
  out->len = len;
  return NGX_OK;
}

/*
 * 函数: ngx_http_waf_join_path
 * 作用: 拼接并规范化路径
 */
ngx_int_t ngx_http_waf_join_path(ngx_pool_t *pool, const ngx_str_t *base_dir, const ngx_str_t *path,
                                 ngx_str_t *out_abs)
{
  if (ngx_http_waf_join_path_internal(pool, base_dir, path, out_abs) != NGX_OK) {
    return NGX_ERROR;
  }
  if (ngx_http_waf_normalize_path(pool, out_abs) != NGX_OK) {
    return NGX_ERROR;
  }
  return NGX_OK;
}

/*
 * 函数: ngx_http_waf_json_read_single
 * 作用: 以宽容模式读取单个 JSON 文件，失败时填充详细错误信息
 */
static yyjson_doc *ngx_http_waf_json_read_single(ngx_pool_t *pool, ngx_log_t *log,
                                                 const ngx_str_t *abs_path,
                                                 ngx_http_waf_json_error_t *err)
{
  yyjson_read_err yerr = {0};
  yyjson_read_flag flags = YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_TRAILING_COMMAS |
                           YYJSON_READ_ALLOW_INF_AND_NAN | YYJSON_READ_ALLOW_EXT_NUMBER |
                           YYJSON_READ_ALLOW_EXT_ESCAPE | YYJSON_READ_ALLOW_EXT_WHITESPACE |
                           YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_UNQUOTED_KEY;

  u_char *path_c = ngx_pnalloc(pool, abs_path->len + 1);
  if (path_c == NULL) {
    if (err) {
      err->file = *abs_path;
      err->json_pointer.len = 0;
      err->json_pointer.data = NULL;
      err->message.len = sizeof("内存不足") - 1;
      err->message.data = (u_char *)"内存不足";
    }
    return NULL;
  }
  ngx_memcpy(path_c, abs_path->data, abs_path->len);
  path_c[abs_path->len] = '\0';

  /* 宽容读取，允许注释/尾逗号/扩展数字等 */
  yyjson_doc *doc = yyjson_read_file((const char *)path_c, flags, NULL, &yerr);
  if (!doc) {
    if (err) {
      err->file = *abs_path;
      err->json_pointer.len = 0;
      err->json_pointer.data = NULL;
      size_t msg_len = yerr.msg ? ngx_strlen(yerr.msg) : 0;
      size_t buf_len = msg_len + 64;
      u_char *buf = ngx_pnalloc(pool, buf_len);
      if (buf) {
        u_char *end = ngx_snprintf(buf, buf_len, "%s at byte %uz",
                                   yerr.msg ? yerr.msg : "yyjson 读取失败", (ngx_uint_t)yerr.pos);
        err->message.data = buf;
        err->message.len = end - buf;
      } else {
        err->message.data = (u_char *)(yerr.msg ? yerr.msg : "yyjson 读取失败");
        err->message.len = msg_len ? msg_len : sizeof("yyjson 读取失败") - 1;
      }
    }
    if (log) {
      ngx_log_error(NGX_LOG_ERR, log, 0, "waf: json read failed: %V", abs_path);
    }
  }
  return doc;
}

/*
 * 函数: ngx_http_waf_resolve_path
 * 作用: 解析 extends 引用：按绝对/相对/jsons_root 解析 -> 展开 Nginx 前缀 ->
 * 规范化
 */
static ngx_int_t ngx_http_waf_resolve_path(ngx_pool_t *pool, ngx_log_t *log,
                                           const ngx_str_t *jsons_root,
                                           const ngx_str_t *current_dir, const ngx_str_t *ref_path,
                                           ngx_str_t *out_abs, ngx_http_waf_json_error_t *err)
{
  ngx_str_t joined;
  ngx_int_t rc;

  if (ref_path->len > 0 && ref_path->data[0] == '/') {
    rc = waf_str_copy(pool, ref_path, &joined);
  } else if (ref_path->len > 1 && ref_path->data[0] == '.') {
    rc = ngx_http_waf_join_path(pool, current_dir, ref_path, &joined);
  } else if (jsons_root && jsons_root->len) {
    rc = ngx_http_waf_join_path(pool, jsons_root, ref_path, &joined);
  } else {
    rc = waf_str_copy(pool, ref_path, &joined);
  }

  if (rc != NGX_OK) {
    if (err) {
      ngx_str_t dummy = {0, NULL};
      waf_json_set_error((waf_merge_ctx_t *)NULL, &dummy, NULL, "路径解析失败");
    }
    return NGX_ERROR;
  }

  /* 展开到完整绝对路径（相对 Nginx Prefix，而非 conf 目录） */
  if (ngx_conf_full_name((ngx_cycle_t *)ngx_cycle, &joined, 0) != NGX_OK) {
    if (err) {
      ngx_str_t dummy = {0, NULL};
      waf_json_set_error((waf_merge_ctx_t *)NULL, &dummy, NULL, "路径展开失败");
    }
    if (log) {
      ngx_log_error(NGX_LOG_ERR, log, 0, "waf: ngx_conf_full_name failed: %V", &joined);
    }
    return NGX_ERROR;
  }

  /* 最终进行路径规范化 */
  if (ngx_http_waf_normalize_path(pool, &joined) != NGX_OK) {
    if (log) {
      ngx_log_error(NGX_LOG_ERR, log, 0, "waf: normalize path failed: %V", &joined);
    }
    return NGX_ERROR;
  }

  *out_abs = joined;
  return NGX_OK;
}

/* ------------------------ 目标解析 ------------------------ */

/* 目标字段到字符串的映射表 */
static const char *waf_target_texts[] = {"CLIENT_IP", "URI", "ALL_PARAMS", "ARGS_COMBINED",
                                         "ARGS_NAME", "ARGS_VALUE", "BODY", "HEADER"};

/*
 * 函数: waf_target_code_from_string
 * 作用: 将目标字段字符串解析为枚举编码
 */
static ngx_int_t waf_target_code_from_string(const char *s, size_t len, waf_target_e *out)
{
  for (ngx_uint_t i = 0; i < WAF_TARGET_ALL_TARGETS; i++) {
    if (ngx_strncmp(s, waf_target_texts[i], len) == 0 && waf_target_texts[i][len] == '\0') {
      *out = (waf_target_e)i;
      return NGX_OK;
    }
  }
  return NGX_ERROR;
}

/*
 * 函数: waf_target_list_contains
 * 作用: 判断目标列表是否包含指定编码
 */
static ngx_uint_t waf_target_list_contains(const waf_target_list_t *list, waf_target_e code)
{
  for (ngx_uint_t i = 0; i < list->count; i++) {
    if (list->items[i] == code) {
      return 1;
    }
  }
  return 0;
}

/*
 * 函数: waf_target_list_add
 * 作用: 添加单个目标编码（去重），并标记 HEADER 存在
 */
static ngx_int_t waf_target_list_add(waf_target_list_t *list, waf_target_e code)
{
  if (code == WAF_TARGET_ALL_PARAMS) {
    return NGX_OK; /* 不直接存储 ALL_PARAMS */
  }
  if (waf_target_list_contains(list, code)) {
    return NGX_OK;
  }
  if (list->count >= WAF_TARGET_ALL_TARGETS) {
    return NGX_ERROR;
  }
  list->items[list->count++] = code;
  if (code == WAF_TARGET_HEADER) {
    list->has_header = 1;
  }
  return NGX_OK;
}

/*
 * 函数: waf_target_list_expand_and_add
 * 作用: 若输入为 ALL_PARAMS，展开为 URI/ARGS_COMBINED/BODY
 */
static ngx_int_t waf_target_list_expand_and_add(waf_target_list_t *list, waf_target_e code)
{
  if (code == WAF_TARGET_ALL_PARAMS) {
    if (waf_target_list_add(list, WAF_TARGET_URI) != NGX_OK)
      return NGX_ERROR;
    if (waf_target_list_add(list, WAF_TARGET_ARGS_COMBINED) != NGX_OK)
      return NGX_ERROR;
    if (waf_target_list_add(list, WAF_TARGET_BODY) != NGX_OK)
      return NGX_ERROR;
    return NGX_OK;
  }
  return waf_target_list_add(list, code);
}

/*
 * 函数: waf_parse_target_value
 * 作用: 解析 JSON 中的 target(字符串或字符串数组)为内部列表
 */
static ngx_int_t waf_parse_target_value(waf_merge_ctx_t *ctx, yyjson_val *node,
                                        const ngx_str_t *file, const char *pointer,
                                        waf_target_list_t *out)
{
  yyjson_type type = yyjson_get_type(node);

  /* 处理单字符串形式 */
  if (type == YYJSON_TYPE_STR) {
    const char *s = yyjson_get_str(node);
    size_t len = yyjson_get_len(node);
    waf_target_e code;
    if (waf_target_code_from_string(s, len, &code) != NGX_OK) {
      return waf_json_set_error(ctx, file, pointer, "target 值 \"%s\" 非法", s);
    }
    if (waf_target_list_expand_and_add(out, code) != NGX_OK) {
      return waf_json_set_error(ctx, file, pointer, "target 列表过长");
    }
    return NGX_OK;
  }

  /* 处理字符串数组形式 */
  if (type == YYJSON_TYPE_ARR) {
    size_t n = yyjson_arr_size(node);
    if (n == 0) {
      return waf_json_set_error(ctx, file, pointer, "target 数组不能为空");
    }
    for (size_t i = 0; i < n; i++) {
      yyjson_val *it = yyjson_arr_get(node, i);
      if (!yyjson_is_str(it)) {
        return waf_json_set_error(ctx, file, pointer, "target 数组元素必须为字符串");
      }
      const char *s = yyjson_get_str(it);
      size_t len = yyjson_get_len(it);
      waf_target_e code;
      if (waf_target_code_from_string(s, len, &code) != NGX_OK) {
        return waf_json_set_error(ctx, file, pointer, "target 值 \"%s\" 非法", s);
      }
      if (waf_target_list_expand_and_add(out, code) != NGX_OK) {
        return waf_json_set_error(ctx, file, pointer, "target 列表过长");
      }
    }
    return NGX_OK;
  }

  return waf_json_set_error(ctx, file, pointer, "target 类型必须为字符串或字符串数组");
}

/*
 * 函数: waf_build_target_mut_value
 * 作用: 将内部列表构造成 yyjson 可变值（字符串或数组）
 */
static yyjson_mut_val *waf_build_target_mut_value(waf_merge_ctx_t *ctx,
                                                  const waf_target_list_t *list)
{
  if (list->count == 0) {
    return NULL;
  }

  if (list->count == 1) {
    const char *s = waf_target_texts[list->items[0]];
    return yyjson_mut_str(ctx->out_doc, s);
  }

  yyjson_mut_val *arr = yyjson_mut_arr(ctx->out_doc);
  if (arr == NULL) {
    return NULL;
  }
  for (ngx_uint_t i = 0; i < list->count; i++) {
    const char *s = waf_target_texts[list->items[i]];
    if (!yyjson_mut_arr_add_str(ctx->out_doc, arr, s)) {
      return NULL;
    }
  }
  return arr;
}

/*
 * 函数: waf_assign_target_to_rule
 * 作用: 将规范化后的 targets 写回规则对象，并校验 HEADER 约束
 */
static ngx_int_t waf_assign_target_to_rule(waf_merge_ctx_t *ctx, yyjson_mut_val *rule,
                                           const waf_target_list_t *list, const ngx_str_t *file,
                                           const char *pointer)
{
  /* 重建规范化的 target 字段 */
  yyjson_mut_val *target_val = waf_build_target_mut_value(ctx, list);
  if (target_val == NULL) {
    return waf_json_set_error(ctx, file, pointer, "分配 target 值失败");
  }

  yyjson_mut_obj_remove_str(rule, "target");
  if (!yyjson_mut_obj_add(rule, yyjson_mut_str(ctx->out_doc, "target"), target_val)) {
    return waf_json_set_error(ctx, file, pointer, "写入 target 失败");
  }

  yyjson_mut_val *header_name = yyjson_mut_obj_get(rule, "headerName");

  if (list->has_header) {
    if (header_name == NULL || !yyjson_is_str((yyjson_val *)header_name)) {
      return waf_json_set_error(ctx, file, pointer, "target 包含 HEADER 时必须提供 headerName");
    }
  } else {
    if (header_name != NULL) {
      yyjson_mut_obj_remove_str(rule, "headerName");
    }
  }

  if (list->has_header && list->count > 1) {
    return waf_json_set_error(ctx, file, pointer, "target 包含 HEADER 时不允许追加其它目标");
  }

  return NGX_OK;
}

/* ------------------------ 规则解析与拷贝 ------------------------ */

/* 已移除未使用的帮助函数，避免 linter 报错 */

/*
 * 函数: waf_string_equals_ci
 * 作用: 等长大小写不敏感比较
 */
static ngx_uint_t waf_string_equals_ci(const char *s, size_t len, const char *target)
{
  size_t tlen = ngx_strlen(target);
  if (len != tlen) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    if (ngx_tolower(s[i]) != ngx_tolower(target[i])) {
      return 0;
    }
  }
  return 1;
}

/*
 * 函数: waf_match_validate
 * 作用: 校验 match 字段的取值是否合法
 */
static ngx_int_t waf_match_validate(const char *s, size_t len)
{
  return (ngx_strncmp(s, "CONTAINS", len) == 0 && len == ngx_strlen("CONTAINS")) ||
         (ngx_strncmp(s, "EXACT", len) == 0 && len == ngx_strlen("EXACT")) ||
         (ngx_strncmp(s, "REGEX", len) == 0 && len == ngx_strlen("REGEX")) ||
         (ngx_strncmp(s, "CIDR", len) == 0 && len == ngx_strlen("CIDR"));
}

/*
 * 函数: waf_action_validate
 * 作用: 校验 action 字段的取值是否合法
 */
static ngx_int_t waf_action_validate(const char *s, size_t len)
{
  return (ngx_strncmp(s, "DENY", len) == 0 && len == ngx_strlen("DENY")) ||
         (ngx_strncmp(s, "LOG", len) == 0 && len == ngx_strlen("LOG")) ||
         (ngx_strncmp(s, "BYPASS", len) == 0 && len == ngx_strlen("BYPASS"));
}

/*
 * 函数: waf_phase_validate
 * 作用: 校验 phase 字段的取值是否合法
 */
static ngx_int_t waf_phase_validate(const char *s, size_t len)
{
  return (ngx_strncmp(s, "ip_allow", len) == 0 && len == ngx_strlen("ip_allow")) ||
         (ngx_strncmp(s, "ip_block", len) == 0 && len == ngx_strlen("ip_block")) ||
         (ngx_strncmp(s, "uri_allow", len) == 0 && len == ngx_strlen("uri_allow")) ||
         (ngx_strncmp(s, "detect", len) == 0 && len == ngx_strlen("detect"));
}

/*
 * 函数: waf_copy_tags_array
 * 作用: 复制并校验 tags 字段（必须为字符串数组）
 */
static ngx_int_t waf_copy_tags_array(waf_merge_ctx_t *ctx, yyjson_val *src,
                                     yyjson_mut_val *rule_mut, const ngx_str_t *file,
                                     const char *pointer)
{
  if (src == NULL) {
    return NGX_OK;
  }
  if (!yyjson_is_arr(src)) {
    return waf_json_set_error(ctx, file, pointer, "tags 必须为字符串数组");
  }
  size_t n = yyjson_arr_size(src);
  yyjson_mut_val *arr = yyjson_mut_arr(ctx->out_doc);
  if (arr == NULL) {
    return waf_json_set_error(ctx, file, pointer, "内存不足");
  }
  for (size_t i = 0; i < n; i++) {
    yyjson_val *it = yyjson_arr_get(src, i);
    if (!yyjson_is_str(it)) {
      return waf_json_set_error(ctx, file, pointer, "tags 元素必须为字符串");
    }
    const char *tag = yyjson_get_str(it);
    if (!yyjson_mut_arr_add_str(ctx->out_doc, arr, tag)) {
      return waf_json_set_error(ctx, file, pointer, "写入 tags 失败");
    }
  }
  yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "tags");
  if (k == NULL) {
    return NGX_ERROR;
  }
  if (!yyjson_mut_obj_add(rule_mut, k, arr)) {
    return waf_json_set_error(ctx, file, pointer, "写入 tags 失败");
  }
  return NGX_OK;
}

/*
 * 函数: waf_rule_has_tag
 * 作用: 判断规则对象是否包含指定 tag
 */
static ngx_uint_t waf_rule_has_tag(yyjson_mut_val *rule, const char *tag)
{
  yyjson_mut_val *tags = yyjson_mut_obj_get(rule, "tags");
  if (tags == NULL || !yyjson_is_arr((yyjson_val *)tags)) {
    return 0;
  }
  size_t n = yyjson_mut_arr_size(tags);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *it = yyjson_mut_arr_get(tags, i);
    if (it && yyjson_is_str((yyjson_val *)it)) {
      const char *s = yyjson_get_str((yyjson_val *)it);
      if (ngx_strcmp(s, tag) == 0) {
        return 1;
      }
    }
  }
  return 0;
}

/*
 * 函数: waf_rule_match_disable_id
 * 作用: 判断 id 是否在 disableById 列表中
 */
static ngx_uint_t waf_rule_match_disable_id(yyjson_val *disable_ids, int64_t id)
{
  if (!disable_ids || !yyjson_is_arr(disable_ids)) {
    return 0;
  }
  size_t n = yyjson_arr_size(disable_ids);
  for (size_t i = 0; i < n; i++) {
    yyjson_val *it = yyjson_arr_get(disable_ids, i);
    if (yyjson_is_int(it) && yyjson_get_sint(it) == id) {
      return 1;
    }
  }
  return 0;
}

/*
 * 函数: waf_rule_match_disable_tag
 * 作用: 判断规则的任意 tag 是否命中 disableByTag
 */
static ngx_uint_t waf_rule_match_disable_tag(yyjson_val *disable_tags, yyjson_mut_val *rule)
{
  if (!disable_tags || !yyjson_is_arr(disable_tags)) {
    return 0;
  }
  yyjson_mut_val *tags = yyjson_mut_obj_get(rule, "tags");
  if (!tags || !yyjson_is_arr((yyjson_val *)tags)) {
    return 0;
  }
  size_t dn = yyjson_arr_size(disable_tags);
  size_t tn = yyjson_mut_arr_size(tags);
  for (size_t i = 0; i < dn; i++) {
    yyjson_val *d = yyjson_arr_get(disable_tags, i);
    if (!yyjson_is_str(d))
      continue;
    const char *target = yyjson_get_str(d);
    for (size_t j = 0; j < tn; j++) {
      yyjson_mut_val *tag = yyjson_mut_arr_get(tags, j);
      if (tag && yyjson_is_str((yyjson_val *)tag)) {
        if (ngx_strcmp(target, yyjson_get_str((yyjson_val *)tag)) == 0) {
          return 1;
        }
      }
    }
  }
  return 0;
}

/*
 * 函数: waf_validate_additional_properties
 * 作用: 校验 rule 对象仅包含允许的字段
 */
static ngx_int_t waf_validate_additional_properties(waf_merge_ctx_t *ctx, yyjson_val *rule,
                                                    const ngx_str_t *file, const char *pointer)
{
  static const char *allowed[] = {"id", "tags", "phase", "target",
                                  "headerName", "match", "pattern", "caseless",
                                  "negate", "action", "score", "priority"};
  size_t allow_count = sizeof(allowed) / sizeof(allowed[0]);

  yyjson_obj_iter it = yyjson_obj_iter_with(rule);
  yyjson_val *key;
  while ((key = yyjson_obj_iter_next(&it))) {
    const char *k = yyjson_get_str(key);
    ngx_uint_t ok = 0;
    for (size_t i = 0; i < allow_count; i++) {
      if (ngx_strcmp(k, allowed[i]) == 0) {
        ok = 1;
        break;
      }
    }
    if (!ok) {
      return waf_json_set_error(ctx, file, pointer, "字段 \"%s\" 不被允许", k);
    }
  }
  return NGX_OK;
}

/*
 * 函数: waf_parse_rule
 * 作用: 解析并规范化单条规则，严格校验字段并构造可变对象
 */
static ngx_int_t waf_parse_rule(waf_merge_ctx_t *ctx, yyjson_val *src_rule, waf_rule_entry_t *out,
                                const ngx_str_t *file, const char *base_pointer)
{
  if (!yyjson_is_obj(src_rule)) {
    return waf_json_set_error(ctx, file, base_pointer, "rule 必须为对象");
  }

  if (waf_validate_additional_properties(ctx, src_rule, file, base_pointer) != NGX_OK) {
    return NGX_ERROR;
  }

  /* 1) 校验 id */
  yyjson_val *id_node = yyjson_obj_get(src_rule, "id");
  if (!id_node || !yyjson_is_int(id_node)) {
    return waf_json_set_error(ctx, file, base_pointer, "缺少必填字段 id 或类型错误");
  }
  int64_t id = yyjson_get_sint(id_node);
  if (id <= 0) {
    return waf_json_set_error(ctx, file, base_pointer, "id 必须为正整数");
  }

  /* 2) 校验 match */
  yyjson_val *match_node = yyjson_obj_get(src_rule, "match");
  if (!match_node || !yyjson_is_str(match_node)) {
    return waf_json_set_error(ctx, file, base_pointer, "缺少必填字段 match");
  }
  const char *match_text = yyjson_get_str(match_node);
  size_t match_len = yyjson_get_len(match_node);
  if (!waf_match_validate(match_text, match_len)) {
    return waf_json_set_error(ctx, file, base_pointer, "match 值非法");
  }

  /* 3) 校验 action */
  yyjson_val *action_node = yyjson_obj_get(src_rule, "action");
  if (!action_node || !yyjson_is_str(action_node)) {
    return waf_json_set_error(ctx, file, base_pointer, "缺少必填字段 action");
  }
  const char *action_text = yyjson_get_str(action_node);
  size_t action_len = yyjson_get_len(action_node);
  if (!waf_action_validate(action_text, action_len)) {
    return waf_json_set_error(ctx, file, base_pointer, "action 值非法");
  }

  /* 4) 解析 target 并归一化 */
  yyjson_val *target_node = yyjson_obj_get(src_rule, "target");
  if (!target_node) {
    return waf_json_set_error(ctx, file, base_pointer, "缺少必填字段 target");
  }

  waf_target_list_t targets;
  ngx_memzero(&targets, sizeof(targets));
  if (waf_parse_target_value(ctx, target_node, file, base_pointer, &targets) != NGX_OK) {
    return NGX_ERROR;
  }
  if (targets.count == 0) {
    return waf_json_set_error(ctx, file, base_pointer, "target 归一化后为空");
  }

  /* 5) HEADER 约束（需要 headerName 且不与其他目标混用） */
  yyjson_val *header_name_node = yyjson_obj_get(src_rule, "headerName");
  if (targets.has_header) {
    if (!header_name_node || !yyjson_is_str(header_name_node)) {
      return waf_json_set_error(ctx, file, base_pointer, "HEADER 目标必须提供 headerName");
    }
    if (targets.count > 1) {
      return waf_json_set_error(ctx, file, base_pointer, "HEADER 目标不允许与其它目标混用");
    }
  } else {
    if (header_name_node) {
      return waf_json_set_error(ctx, file, base_pointer, "非 HEADER 目标禁止出现 headerName");
    }
  }

  /* 6) 校验 pattern（字符串或非空字符串数组） */
  yyjson_val *pattern_node = yyjson_obj_get(src_rule, "pattern");
  if (!pattern_node) {
    return waf_json_set_error(ctx, file, base_pointer, "缺少必填字段 pattern");
  }

  yyjson_type pattern_type = yyjson_get_type(pattern_node);
  if (pattern_type != YYJSON_TYPE_STR && pattern_type != YYJSON_TYPE_ARR) {
    return waf_json_set_error(ctx, file, base_pointer, "pattern 必须为字符串或字符串数组");
  }

  if (yyjson_is_arr(pattern_node) && yyjson_arr_size(pattern_node) == 0) {
    return waf_json_set_error(ctx, file, base_pointer, "pattern 数组不能为空");
  }

  if (yyjson_is_arr(pattern_node)) {
    size_t pn = yyjson_arr_size(pattern_node);
    for (size_t i = 0; i < pn; i++) {
      yyjson_val *it = yyjson_arr_get(pattern_node, i);
      if (!yyjson_is_str(it)) {
        return waf_json_set_error(ctx, file, base_pointer, "pattern 数组元素必须为字符串");
      }
    }
  }

  /* 7) 语义约束: action=BYPASS 时禁止 score */
  if (waf_string_equals_ci(action_text, action_len, "bypass")) {
    yyjson_val *score_node = yyjson_obj_get(src_rule, "score");
    if (score_node && yyjson_is_num(score_node)) {
      return waf_json_set_error(ctx, file, base_pointer, "action=BYPASS 时禁止出现 score");
    }
  }

  yyjson_val *phase_node = yyjson_obj_get(src_rule, "phase");
  if (phase_node) {
    if (!yyjson_is_str(phase_node)) {
      return waf_json_set_error(ctx, file, base_pointer, "phase 必须为字符串");
    }
    const char *phase_text = yyjson_get_str(phase_node);
    size_t phase_len = yyjson_get_len(phase_node);
    if (!waf_phase_validate(phase_text, phase_len)) {
      return waf_json_set_error(ctx, file, base_pointer, "phase 取值非法");
    }
  }

  yyjson_val *caseless_node = yyjson_obj_get(src_rule, "caseless");
  if (caseless_node && !yyjson_is_bool(caseless_node)) {
    return waf_json_set_error(ctx, file, base_pointer, "caseless 必须为布尔值");
  }

  yyjson_val *negate_node = yyjson_obj_get(src_rule, "negate");
  if (negate_node && !yyjson_is_bool(negate_node)) {
    return waf_json_set_error(ctx, file, base_pointer, "negate 必须为布尔值");
  }

  yyjson_val *score_node = yyjson_obj_get(src_rule, "score");
  if (score_node && !yyjson_is_num(score_node)) {
    return waf_json_set_error(ctx, file, base_pointer, "score 必须为数字");
  }

  yyjson_val *priority_node = yyjson_obj_get(src_rule, "priority");
  if (priority_node && !yyjson_is_num(priority_node)) {
    return waf_json_set_error(ctx, file, base_pointer, "priority 必须为数字");
  }

  /* 8) 构建可变对象并填充字段 */
  yyjson_mut_val *rule_mut = yyjson_mut_obj(ctx->out_doc);
  if (rule_mut == NULL) {
    return waf_json_set_error(ctx, file, base_pointer, "内存不足");
  }

  yyjson_mut_val *k_id = yyjson_mut_str(ctx->out_doc, "id");
  yyjson_mut_val *v_id = yyjson_mut_sint(ctx->out_doc, id);
  if (!k_id || !v_id || !yyjson_mut_obj_add(rule_mut, k_id, v_id)) {
    return waf_json_set_error(ctx, file, base_pointer, "写入 id 失败");
  }

  if (waf_copy_tags_array(ctx, yyjson_obj_get(src_rule, "tags"), rule_mut, file, base_pointer) !=
      NGX_OK) {
    return NGX_ERROR;
  }

  if (phase_node) {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "phase");
    yyjson_mut_val *v = yyjson_mut_str(ctx->out_doc, yyjson_get_str(phase_node));
    if (!k || !v || !yyjson_mut_obj_add(rule_mut, k, v)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 phase 失败");
    }
  }

  if (header_name_node) {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "headerName");
    yyjson_mut_val *v = yyjson_mut_str(ctx->out_doc, yyjson_get_str(header_name_node));
    if (!k || !v || !yyjson_mut_obj_add(rule_mut, k, v)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 headerName 失败");
    }
  }

  if (waf_assign_target_to_rule(ctx, rule_mut, &targets, file, base_pointer) != NGX_OK) {
    return NGX_ERROR;
  }

  yyjson_mut_val *k_match = yyjson_mut_str(ctx->out_doc, "match");
  yyjson_mut_val *v_match = yyjson_mut_str(ctx->out_doc, match_text);
  if (!k_match || !v_match || !yyjson_mut_obj_add(rule_mut, k_match, v_match)) {
    return waf_json_set_error(ctx, file, base_pointer, "写入 match 失败");
  }

  /* 9) 写入 pattern（字符串或数组） */
  if (pattern_type == YYJSON_TYPE_STR) {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "pattern");
    size_t plen = yyjson_get_len(pattern_node);
    if (plen == 0) {
      return waf_json_set_error(ctx, file, base_pointer, "pattern 字符串不能为空");
    }
    yyjson_mut_val *v = yyjson_mut_str(ctx->out_doc, yyjson_get_str(pattern_node));
    if (!k || !v || !yyjson_mut_obj_add(rule_mut, k, v)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 pattern 失败");
    }
  } else {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "pattern");
    yyjson_mut_val *arr = yyjson_mut_arr(ctx->out_doc);
    if (!k || !arr) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 pattern 失败");
    }
    size_t pn = yyjson_arr_size(pattern_node);
    for (size_t i = 0; i < pn; i++) {
      yyjson_val *it = yyjson_arr_get(pattern_node, i);
      if (!yyjson_is_str(it)) {
        return waf_json_set_error(ctx, file, base_pointer, "pattern 数组元素必须为字符串");
      }
      if (yyjson_get_len(it) == 0) {
        return waf_json_set_error(ctx, file, base_pointer, "pattern 数组元素不能为空字符串");
      }
      if (!yyjson_mut_arr_add_str(ctx->out_doc, arr, yyjson_get_str(it))) {
        return waf_json_set_error(ctx, file, base_pointer, "写入 pattern 失败");
      }
    }
    if (!yyjson_mut_obj_add(rule_mut, k, arr)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 pattern 失败");
    }
  }

  yyjson_mut_val *k_action = yyjson_mut_str(ctx->out_doc, "action");
  yyjson_mut_val *v_action = yyjson_mut_str(ctx->out_doc, action_text);
  if (!k_action || !v_action || !yyjson_mut_obj_add(rule_mut, k_action, v_action)) {
    return waf_json_set_error(ctx, file, base_pointer, "写入 action 失败");
  }

  if (caseless_node) {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "caseless");
    yyjson_mut_val *v = yyjson_is_true(caseless_node) ? yyjson_mut_true(ctx->out_doc)
                                                      : yyjson_mut_false(ctx->out_doc);
    if (!k || !v || !yyjson_mut_obj_add(rule_mut, k, v)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 caseless 失败");
    }
  }

  if (negate_node) {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "negate");
    yyjson_mut_val *v = yyjson_is_true(negate_node) ? yyjson_mut_true(ctx->out_doc)
                                                    : yyjson_mut_false(ctx->out_doc);
    if (!k || !v || !yyjson_mut_obj_add(rule_mut, k, v)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 negate 失败");
    }
  }

  if (score_node) {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "score");
    yyjson_mut_val *v;
    if (yyjson_is_int(score_node)) {
      v = yyjson_mut_sint(ctx->out_doc, yyjson_get_sint(score_node));
    } else {
      v = yyjson_mut_real(ctx->out_doc, yyjson_get_real(score_node));
    }
    if (!k || !v || !yyjson_mut_obj_add(rule_mut, k, v)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 score 失败");
    }
  }

  if (priority_node) {
    yyjson_mut_val *k = yyjson_mut_str(ctx->out_doc, "priority");
    yyjson_mut_val *v;
    if (yyjson_is_int(priority_node)) {
      v = yyjson_mut_sint(ctx->out_doc, yyjson_get_sint(priority_node));
    } else {
      v = yyjson_mut_real(ctx->out_doc, yyjson_get_real(priority_node));
    }
    if (!k || !v || !yyjson_mut_obj_add(rule_mut, k, v)) {
      return waf_json_set_error(ctx, file, base_pointer, "写入 priority 失败");
    }
  }

  /* 10) 返回输出条目 */
  out->id = id;
  out->rule = rule_mut;
  if (waf_str_copy(ctx->pool, file, &out->file) != NGX_OK) {
    return waf_json_set_error(ctx, file, base_pointer, "内存不足");
  }
  if (waf_pointer_concat(ctx->pool, base_pointer, "", &out->pointer) != NGX_OK) {
    return waf_json_set_error(ctx, file, base_pointer, "内存不足");
  }

  return NGX_OK;
}

/* ------------------------ 重复策略 ------------------------ */

/*
 * 函数: waf_parse_duplicate_policy
 * 作用: 读取 duplicatePolicy，默认 warn_skip
 */
static waf_dup_policy_e waf_parse_duplicate_policy(yyjson_val *root)
{
  yyjson_val *meta = yyjson_obj_get(root, "meta");
  yyjson_val *dp = NULL;
  if (meta) {
    dp = yyjson_obj_get(meta, "duplicatePolicy");
  }
  if (!dp) {
    dp = yyjson_obj_get(root, "duplicatePolicy");
  }
  if (dp && yyjson_is_str(dp)) {
    const char *s = yyjson_get_str(dp);
    if (ngx_strcmp(s, "warn_keep_last") == 0) {
      return WAF_DUP_POLICY_WARN_KEEP_LAST;
    }
    if (ngx_strcmp(s, "error") == 0) {
      return WAF_DUP_POLICY_ERROR;
    }
    if (ngx_strcmp(s, "warn_skip") == 0) {
      return WAF_DUP_POLICY_WARN_SKIP;
    }
  }
  return WAF_DUP_POLICY_WARN_SKIP;
}

/* ------------------------ 重写计划解析/应用 ------------------------ */

/*
 * 函数: waf_parse_target_list_from_val
 * 作用: 从 JSON 值解析 target 列表（包装器）
 */
static ngx_int_t waf_parse_target_list_from_val(waf_merge_ctx_t *ctx, yyjson_val *node,
                                                const ngx_str_t *file, const char *pointer,
                                                waf_target_list_t *out)
{
  ngx_memzero(out, sizeof(*out));
  return waf_parse_target_value(ctx, node, file, pointer, out);
}

/*
 * 函数: waf_parse_rewrite_plan
 * 作用: 解析 extends 对象中的重写计划（按 tag/ids 改写 target）
 */
static ngx_int_t waf_parse_rewrite_plan(waf_merge_ctx_t *ctx, yyjson_val *plan_obj,
                                        const ngx_str_t *file, const char *base_pointer,
                                        waf_rewrite_plan_t *plan)
{
  ngx_memzero(plan, sizeof(*plan));

  if (!plan_obj || !yyjson_is_obj(plan_obj)) {
    return waf_json_set_error(ctx, file, base_pointer, "extends 对象需包含 file 字段");
  }

  plan->tag_rules = ngx_array_create(ctx->pool, 2, sizeof(waf_rewrite_tag_rule_t));
  plan->id_rules = ngx_array_create(ctx->pool, 2, sizeof(waf_rewrite_ids_rule_t));
  if (plan->tag_rules == NULL || plan->id_rules == NULL) {
    return waf_json_set_error(ctx, file, base_pointer, "内存不足");
  }

  yyjson_val *tag_map = yyjson_obj_get(plan_obj, "rewriteTargetsForTag");
  if (tag_map) {
    if (!yyjson_is_obj(tag_map)) {
      return waf_json_set_error(ctx, file, base_pointer, "rewriteTargetsForTag 必须为对象");
    }
    yyjson_obj_iter it = yyjson_obj_iter_with(tag_map);
    yyjson_val *key;
    while ((key = yyjson_obj_iter_next(&it))) {
      const char *tag = yyjson_get_str(key);
      yyjson_val *val = yyjson_obj_iter_get_val(key);
      waf_rewrite_tag_rule_t *rule = ngx_array_push(plan->tag_rules);
      if (!rule) {
        return waf_json_set_error(ctx, file, base_pointer, "内存不足");
      }
      ngx_memzero(rule, sizeof(*rule));
      size_t tag_len = ngx_strlen(tag);
      u_char *tag_copy = ngx_pnalloc(ctx->pool, tag_len);
      if (!tag_copy) {
        return waf_json_set_error(ctx, file, base_pointer, "内存不足");
      }
      ngx_memcpy(tag_copy, tag, tag_len);
      rule->tag.data = tag_copy;
      rule->tag.len = tag_len;

      if (waf_pointer_concat(ctx->pool, base_pointer, "/rewriteTargetsForTag", &rule->pointer) !=
          NGX_OK) {
        return waf_json_set_error(ctx, file, base_pointer, "内存不足");
      }
      if (waf_parse_target_list_from_val(ctx, val, file, base_pointer, &rule->targets) != NGX_OK) {
        return NGX_ERROR;
      }
    }
  }

  yyjson_val *id_arr = yyjson_obj_get(plan_obj, "rewriteTargetsForIds");
  if (id_arr) {
    if (!yyjson_is_arr(id_arr)) {
      return waf_json_set_error(ctx, file, base_pointer, "rewriteTargetsForIds 必须为数组");
    }
    size_t n = yyjson_arr_size(id_arr);
    for (size_t i = 0; i < n; i++) {
      yyjson_val *obj = yyjson_arr_get(id_arr, i);
      if (!yyjson_is_obj(obj)) {
        return waf_json_set_error(ctx, file, base_pointer, "rewriteTargetsForIds 元素必须为对象");
      }
      yyjson_val *ids = yyjson_obj_get(obj, "ids");
      yyjson_val *target = yyjson_obj_get(obj, "target");
      if (!ids || !yyjson_is_arr(ids) || !target) {
        return waf_json_set_error(ctx, file, base_pointer,
                                  "rewriteTargetsForIds 对象需包含 ids 数组与 target");
      }
      waf_rewrite_ids_rule_t *rule = ngx_array_push(plan->id_rules);
      if (!rule) {
        return waf_json_set_error(ctx, file, base_pointer, "内存不足");
      }
      ngx_memzero(rule, sizeof(*rule));
      rule->ids = ngx_array_create(ctx->pool, 2, sizeof(int64_t));
      if (!rule->ids) {
        return waf_json_set_error(ctx, file, base_pointer, "内存不足");
      }
      size_t m = yyjson_arr_size(ids);
      if (m == 0) {
        return waf_json_set_error(ctx, file, base_pointer, "rewriteTargetsForIds.ids 不能为空");
      }
      for (size_t j = 0; j < m; j++) {
        yyjson_val *it = yyjson_arr_get(ids, j);
        if (!yyjson_is_int(it)) {
          return waf_json_set_error(ctx, file, base_pointer,
                                    "rewriteTargetsForIds.ids 元素必须为整数");
        }
        int64_t *slot = ngx_array_push(rule->ids);
        if (!slot) {
          return waf_json_set_error(ctx, file, base_pointer, "内存不足");
        }
        *slot = yyjson_get_sint(it);
      }
      if (waf_parse_target_list_from_val(ctx, target, file, base_pointer, &rule->targets) !=
          NGX_OK) {
        return NGX_ERROR;
      }
      if (waf_pointer_concat(ctx->pool, base_pointer, "/rewriteTargetsForIds", &rule->pointer) !=
          NGX_OK) {
        return waf_json_set_error(ctx, file, base_pointer, "内存不足");
      }
    }
  }

  return NGX_OK;
}

static ngx_int_t waf_apply_rewrite_plan(waf_merge_ctx_t *ctx, waf_rewrite_plan_t *plan,
                                        ngx_array_t *rules)
{
  if (!plan || (!plan->tag_rules && !plan->id_rules)) {
    return NGX_OK;
  }

  waf_rule_entry_t *entries = rules->elts;
  ngx_uint_t rule_count = rules->nelts;

  if (plan->tag_rules) {
    waf_rewrite_tag_rule_t *tag_rules = plan->tag_rules->elts;
    ngx_uint_t tn = plan->tag_rules->nelts;
    for (ngx_uint_t i = 0; i < tn; i++) {
      waf_rewrite_tag_rule_t *r = &tag_rules[i];
      for (ngx_uint_t j = 0; j < rule_count; j++) {
        yyjson_mut_val *rule = entries[j].rule;
        if (waf_rule_has_tag(rule, (const char *)r->tag.data)) {
          if (waf_assign_target_to_rule(ctx, rule, &r->targets, &entries[j].file,
                                        (const char *)r->pointer.data) != NGX_OK) {
            return NGX_ERROR;
          }
        }
      }
    }
  }

  if (plan->id_rules) {
    waf_rewrite_ids_rule_t *id_rules = plan->id_rules->elts;
    ngx_uint_t in = plan->id_rules->nelts;
    for (ngx_uint_t i = 0; i < in; i++) {
      waf_rewrite_ids_rule_t *r = &id_rules[i];
      int64_t *id_list = r->ids->elts;
      ngx_uint_t idn = r->ids->nelts;
      for (ngx_uint_t j = 0; j < rule_count; j++) {
        for (ngx_uint_t k = 0; k < idn; k++) {
          if (entries[j].id == id_list[k]) {
            if (waf_assign_target_to_rule(ctx, entries[j].rule, &r->targets, &entries[j].file,
                                          (const char *)r->pointer.data) != NGX_OK) {
              return NGX_ERROR;
            }
            break;
          }
        }
      }
    }
  }

  return NGX_OK;
}

/* ------------------------ 规则集合操作 ------------------------ */

/* 基于 uthash 的 id->index 查重项（仅在单层合并期使用） */
typedef struct {
  int64_t id;
  ngx_uint_t idx;    /* 在 result->elts 中的位置 */
  ngx_str_t file;    /* 首次（或最近一次 keep_last 后）来源 */
  ngx_str_t pointer; /* 首次（或最近一次 keep_last 后）JSON 指针 */
  UT_hash_handle hh;
} waf_id_idx_entry_t;

/* 依据 duplicatePolicy 写入规则（O(1) 查重），保持既有语义/日志不变 */
static ngx_int_t waf_append_rule_with_policy_hashed(waf_merge_ctx_t *ctx, ngx_array_t *result,
                                                    waf_id_idx_entry_t **id_map,
                                                    const waf_rule_entry_t *entry,
                                                    waf_dup_policy_e policy)
{
  waf_id_idx_entry_t *found = NULL;
  HASH_FIND(hh, *id_map, &entry->id, sizeof(entry->id), found);

  if (found) {
    switch (policy) {
      case WAF_DUP_POLICY_ERROR:
        return waf_json_set_error(ctx, &entry->file, (const char *)entry->pointer.data,
                                  "重复规则 id=%L (duplicatePolicy=error)", entry->id);
      case WAF_DUP_POLICY_WARN_SKIP:
        if (ctx->log) {
          ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                        "waf: duplicate rule id=%L, skip (policy=warn_skip)", entry->id);
        }
        return NGX_OK;
      case WAF_DUP_POLICY_WARN_KEEP_LAST: {
        /* 就地覆盖首个位置，保持保序语义与原日志格式 */
        waf_rule_entry_t *items = result->elts;
        if (ctx->log) {
          ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                        "waf: duplicate rule id=%L, keep last (policy=warn_keep_last)", entry->id);
        }
        items[found->idx] = *entry;
        /* 更新来源，便于后续再次冲突时参考（不影响现有日志格式） */
        found->file = entry->file;
        found->pointer = entry->pointer;
        return NGX_OK;
      }
    }
  }

  /* 首次出现：追加并登记索引 */
  waf_rule_entry_t *slot = ngx_array_push(result);
  if (slot == NULL) {
    return waf_json_set_error(ctx, &entry->file, (const char *)entry->pointer.data, "内存不足");
  }
  *slot = *entry;

  waf_id_idx_entry_t *e = ngx_pcalloc(ctx->pool, sizeof(*e));
  if (e == NULL) {
    return waf_json_set_error(ctx, &entry->file, (const char *)entry->pointer.data, "内存不足");
  }
  e->id = entry->id;
  e->idx = result->nelts - 1;
  e->file = entry->file;
  e->pointer = entry->pointer;
  HASH_ADD(hh, *id_map, id, sizeof(e->id), e);
  return NGX_OK;
}

/* 线性查重版本已移除，使用哈希索引版本替代 */
/*
 * 函数: waf_append_rule_with_policy
 * 作用: 依据 duplicatePolicy 写入规则，采用线性查重
 */
//  static ngx_int_t
//  waf_append_rule_with_policy(waf_merge_ctx_t* ctx,
//                              ngx_array_t* result,
//                              const waf_rule_entry_t* entry,
//                              waf_dup_policy_e policy)
//  {
//      waf_rule_entry_t* items = result->elts;
//      for (ngx_uint_t i = 0; i < result->nelts; i++) {
//          if (items[i].id == entry->id) {
//              switch (policy) {
//              case WAF_DUP_POLICY_ERROR:
//                  return waf_json_set_error(ctx, &entry->file, (const
//                  char*)entry->pointer.data,
//                                            "重复规则 id=%L
//                                            (duplicatePolicy=error)",
//                                            entry->id);
//              case WAF_DUP_POLICY_WARN_SKIP:
//                  if (ctx->log) {
//                      ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
//                                    "waf: duplicate rule id=%L, skip
//                                    (policy=warn_skip)", entry->id);
//                  }
//                  return NGX_OK;
//              case WAF_DUP_POLICY_WARN_KEEP_LAST:
//                  if (ctx->log) {
//                      ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
//                                    "waf: duplicate rule id=%L, keep last
//                                    (policy=warn_keep_last)", entry->id);
//                  }
//                  items[i] = *entry;
//                  return NGX_OK;
//              }
//          }
//      }

//      waf_rule_entry_t* slot = ngx_array_push(result);
//      if (slot == NULL) {
//          return waf_json_set_error(ctx, &entry->file, (const
//          char*)entry->pointer.data, "内存不足");
//      }
//      *slot = *entry;
//      return NGX_OK;
//  }

/*
 * 函数: waf_merge_append_array
 * 作用: 将 src 规则数组整体追加到 dest（不做去重）
 */
static ngx_int_t waf_merge_append_array(ngx_array_t *dest, ngx_array_t *src)
{
  if (!src || src->nelts == 0) {
    return NGX_OK;
  }
  waf_rule_entry_t *entries = ngx_array_push_n(dest, src->nelts);
  if (!entries) {
    return NGX_ERROR;
  }
  ngx_memcpy(entries, src->elts, sizeof(waf_rule_entry_t) * src->nelts);
  return NGX_OK;
}

/* ------------------------ 主递归 ------------------------ */

static ngx_int_t waf_collect_rules(waf_merge_ctx_t *ctx, const ngx_str_t *abs_path,
                                   ngx_uint_t depth, ngx_array_t **out_rules);

/*
 * 函数: waf_collect_rules
 * 作用: 递归收集并合并规则：处理 extends/重写/禁用/去重/本地 rules
 */
static ngx_int_t waf_collect_rules(waf_merge_ctx_t *ctx, const ngx_str_t *abs_path,
                                   ngx_uint_t depth, ngx_array_t **out_rules)
{
  /* 深度上限保护 */
  if (ctx->max_depth != 0 && depth > ctx->max_depth) {
    return waf_json_set_error(ctx, abs_path, NULL, "extends 递归深度超出上限");
  }

  /* 环检测：路径重复即视为循环 */
  if (ngx_http_waf_path_in_stack(ctx->stack, abs_path)) {
    /* 与测试脚本关键字对齐（同时保留中文语义） */
    return waf_json_set_error(ctx, abs_path, NULL,
                              "extends cycle detected | 检测到 extends 循环引用");
  }

  /* 入栈，函数尾部出栈 */
  if (ngx_http_waf_push_path(ctx->stack, abs_path) != NGX_OK) {
    return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
  }

  ngx_http_waf_json_error_t reader_err;
  waf_json_reset_error(&reader_err);
  yyjson_doc *doc = ngx_http_waf_json_read_single(ctx->pool, ctx->log, abs_path, &reader_err);
  if (doc == NULL) {
    ctx->stack->nelts--;
    return waf_json_set_error(ctx, abs_path, (const char *)reader_err.json_pointer.data, "%V",
                              &reader_err.message);
  }

  yyjson_val *root = yyjson_doc_get_root(doc);
  if (!root || !yyjson_is_obj(root)) {
    yyjson_doc_free(doc);
    ctx->stack->nelts--;
    return waf_json_set_error(ctx, abs_path, NULL, "规则文件顶层必须为对象");
  }

  /* 读取重复策略 */
  waf_dup_policy_e policy = waf_parse_duplicate_policy(root);

  ngx_array_t *result = ngx_array_create(ctx->pool, 8, sizeof(waf_rule_entry_t));
  if (!result) {
    yyjson_doc_free(doc);
    ctx->stack->nelts--;
    return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
  }

  ngx_array_t *imported = ngx_array_create(ctx->pool, 4, sizeof(waf_rule_entry_t));
  if (!imported) {
    yyjson_doc_free(doc);
    ctx->stack->nelts--;
    return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
  }

  /* 本层去重索引（O(1)）：id -> index */
  waf_id_idx_entry_t *id_map = NULL;

  yyjson_val *meta = yyjson_obj_get(root, "meta");
  yyjson_val *extends = NULL;
  if (meta) {
    extends = yyjson_obj_get(meta, "extends");
    if (extends && !yyjson_is_arr(extends)) {
      yyjson_doc_free(doc);
      ctx->stack->nelts--;
      HASH_CLEAR(hh, id_map);
      return waf_json_set_error(ctx, abs_path, "/meta/extends", "meta.extends 必须为数组");
    }
  }

  ngx_str_t current_dir;
  if (ngx_http_waf_dirname(ctx->pool, abs_path, &current_dir) != NGX_OK) {
    yyjson_doc_free(doc);
    ctx->stack->nelts--;
    HASH_CLEAR(hh, id_map);
    return waf_json_set_error(ctx, abs_path, NULL, "解析目录失败");
  }

  if (extends) {
    size_t en = yyjson_arr_size(extends);
    for (size_t i = 0; i < en; i++) {
      yyjson_val *item = yyjson_arr_get(extends, i);
      ngx_str_t pointer;
      u_char tmp[64];
      u_char *end = ngx_snprintf(tmp, sizeof(tmp), "/meta/extends[%uz]", (ngx_uint_t)i);
      size_t plen = end - tmp;
      u_char *p_ptr = ngx_pnalloc(ctx->pool, plen + 1);
      if (p_ptr == NULL) {
        yyjson_doc_free(doc);
        ctx->stack->nelts--;
        HASH_CLEAR(hh, id_map);
        return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
      }
      ngx_memcpy(p_ptr, tmp, plen);
      p_ptr[plen] = '\0';
      pointer.data = p_ptr;
      pointer.len = plen;

      ngx_str_t child_ref;
      waf_rewrite_plan_t plan;
      ngx_memzero(&plan, sizeof(plan));
      ngx_int_t rc;
      (void)rc; /* suppress unused warning */

      yyjson_val *file_node = NULL;
      if (yyjson_is_str(item)) {
        const char *s = yyjson_get_str(item);
        size_t sl = yyjson_get_len(item);
        u_char *p = ngx_pnalloc(ctx->pool, sl);
        if (!p) {
          yyjson_doc_free(doc);
          ctx->stack->nelts--;
          HASH_CLEAR(hh, id_map);
          return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
        }
        ngx_memcpy(p, s, sl);
        child_ref.data = p;
        child_ref.len = sl;
      } else if (yyjson_is_obj(item)) {
        file_node = yyjson_obj_get(item, "file");
        if (!file_node || !yyjson_is_str(file_node)) {
          yyjson_doc_free(doc);
          ctx->stack->nelts--;
          return waf_json_set_error(ctx, abs_path, "/meta/extends[]",
                                    "extends 对象必须包含 file 字段");
        }
        const char *s = yyjson_get_str(file_node);
        size_t sl = yyjson_get_len(file_node);
        u_char *p = ngx_pnalloc(ctx->pool, sl);
        if (!p) {
          yyjson_doc_free(doc);
          ctx->stack->nelts--;
          return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
        }
        ngx_memcpy(p, s, sl);
        child_ref.data = p;
        child_ref.len = sl;
        if (waf_parse_rewrite_plan(ctx, item, abs_path, (const char *)pointer.data, &plan) !=
            NGX_OK) {
          yyjson_doc_free(doc);
          ctx->stack->nelts--;
          HASH_CLEAR(hh, id_map);
          return NGX_ERROR;
        }
      } else {
        yyjson_doc_free(doc);
        ctx->stack->nelts--;
        HASH_CLEAR(hh, id_map);
        return waf_json_set_error(ctx, abs_path, "/meta/extends[]",
                                  "extends 元素必须为字符串或对象");
      }

      ngx_str_t child_abs;
      if (ngx_http_waf_resolve_path(ctx->pool, ctx->log, &ctx->jsons_root, &current_dir, &child_ref,
                                    &child_abs, ctx->err) != NGX_OK) {
        yyjson_doc_free(doc);
        ctx->stack->nelts--;
        HASH_CLEAR(hh, id_map);
        return waf_json_set_error(ctx, abs_path, (const char *)pointer.data,
                                  "extends 路径解析失败");
      }

      /* 递归收集子规则 */
      ngx_array_t *child_rules = NULL;
      if (waf_collect_rules(ctx, &child_abs, depth + 1, &child_rules) != NGX_OK) {
        yyjson_doc_free(doc);
        ctx->stack->nelts--;
        HASH_CLEAR(hh, id_map);
        return NGX_ERROR;
      }

      /* 应用重写计划（若存在） */
      if (plan.tag_rules || plan.id_rules) {
        if (waf_apply_rewrite_plan(ctx, &plan, child_rules) != NGX_OK) {
          yyjson_doc_free(doc);
          ctx->stack->nelts--;
          HASH_CLEAR(hh, id_map);
          return NGX_ERROR;
        }
      }

      /* 将导入集合暂存到 imported */
      if (waf_merge_append_array(imported, child_rules) != NGX_OK) {
        yyjson_doc_free(doc);
        ctx->stack->nelts--;
        HASH_CLEAR(hh, id_map);
        return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
      }
    }
  }

  yyjson_val *disable_by_id = yyjson_obj_get(root, "disableById");
  if (disable_by_id && !yyjson_is_arr(disable_by_id)) {
    yyjson_doc_free(doc);
    ctx->stack->nelts--;
    HASH_CLEAR(hh, id_map);
    return waf_json_set_error(ctx, abs_path, "/disableById", "disableById 必须为数组");
  }
  yyjson_val *disable_by_tag = yyjson_obj_get(root, "disableByTag");
  if (disable_by_tag && !yyjson_is_arr(disable_by_tag)) {
    yyjson_doc_free(doc);
    ctx->stack->nelts--;
    HASH_CLEAR(hh, id_map);
    return waf_json_set_error(ctx, abs_path, "/disableByTag", "disableByTag 必须为数组");
  }

  if (imported->nelts > 0) {
    waf_rule_entry_t *entries = imported->elts;
    ngx_array_t *filtered = ngx_array_create(ctx->pool, imported->nelts, sizeof(waf_rule_entry_t));
    if (!filtered) {
      yyjson_doc_free(doc);
      ctx->stack->nelts--;
      HASH_CLEAR(hh, id_map);
      return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
    }
    /* 先过滤禁用项，再按策略合并 */
    for (ngx_uint_t i = 0; i < imported->nelts; i++) {
      waf_rule_entry_t *entry = &entries[i];
      if (waf_rule_match_disable_id(disable_by_id, entry->id)) {
        continue;
      }
      if (waf_rule_match_disable_tag(disable_by_tag, entry->rule)) {
        continue;
      }
      waf_rule_entry_t *slot = ngx_array_push(filtered);
      if (!slot) {
        yyjson_doc_free(doc);
        ctx->stack->nelts--;
        HASH_CLEAR(hh, id_map);
        return waf_json_set_error(ctx, abs_path, NULL, "内存不足");
      }
      *slot = *entry;
    }

    waf_rule_entry_t *filtered_entries = filtered->elts;
    for (ngx_uint_t i = 0; i < filtered->nelts; i++) {
      if (waf_append_rule_with_policy_hashed(ctx, result, &id_map, &filtered_entries[i], policy) !=
          NGX_OK) {
        yyjson_doc_free(doc);
        ctx->stack->nelts--;
        HASH_CLEAR(hh, id_map);
        return NGX_ERROR;
      }
    }
  }

  yyjson_val *rules_arr = yyjson_obj_get(root, "rules");
  if (!rules_arr || !yyjson_is_arr(rules_arr)) {
    yyjson_doc_free(doc);
    ctx->stack->nelts--;
    HASH_CLEAR(hh, id_map);
    return waf_json_set_error(ctx, abs_path, "/rules", "缺少必填字段 rules 或类型错误");
  }

  /* 处理当前文件的本地 rules */
  size_t rn = yyjson_arr_size(rules_arr);
  for (size_t i = 0; i < rn; i++) {
    yyjson_val *rule_node = yyjson_arr_get(rules_arr, i);
    char pointer_buf[32];
    ngx_snprintf((u_char *)pointer_buf, sizeof(pointer_buf), "/rules[%uz]", (ngx_uint_t)i);
    waf_rule_entry_t entry;
    if (waf_parse_rule(ctx, rule_node, &entry, abs_path, pointer_buf) != NGX_OK) {
      yyjson_doc_free(doc);
      ctx->stack->nelts--;
      HASH_CLEAR(hh, id_map);
      return NGX_ERROR;
    }
    if (waf_append_rule_with_policy_hashed(ctx, result, &id_map, &entry, policy) != NGX_OK) {
      yyjson_doc_free(doc);
      ctx->stack->nelts--;
      HASH_CLEAR(hh, id_map);
      return NGX_ERROR;
    }
  }

  yyjson_doc_free(doc);
  ctx->stack->nelts--;
  /* 清理 uthash 表结构（元素由 pool 承载） */
  HASH_CLEAR(hh, id_map);
  *out_rules = result;
  return NGX_OK;
}

/* ------------------------ 对外入口 ------------------------ */

/*
 * 函数: ngx_http_waf_json_load_and_merge
 * 作用: 加载并合并入口规则文件（含 extends 链），输出最终不可变 yyjson 文档
 */
yyjson_doc *ngx_http_waf_json_load_and_merge(ngx_pool_t *pool, ngx_log_t *log,
                                             const ngx_str_t *base_dir, const ngx_str_t *entry_path,
                                             ngx_uint_t max_depth, ngx_http_waf_json_error_t *err)
{
  if (pool == NULL || entry_path == NULL) {
    return NULL;
  }

  waf_merge_ctx_t ctx;
  ngx_memzero(&ctx, sizeof(ctx));
  ctx.pool = pool;
  ctx.log = log;
  ctx.err = err;
  ctx.max_depth = max_depth;

  if (base_dir) {
    ctx.jsons_root = *base_dir;
  } else {
    ctx.jsons_root.len = 0;
    ctx.jsons_root.data = NULL;
  }

  ctx.stack = ngx_array_create(pool, 8, sizeof(ngx_str_t));
  if (ctx.stack == NULL) {
    return NULL;
  }

  ctx.out_doc = yyjson_mut_doc_new(NULL);
  if (ctx.out_doc == NULL) {
    return NULL;
  }

  /* 清空错误对象，保证可预测状态 */
  waf_json_reset_error(err);

  ngx_str_t abs;
  if (ngx_http_waf_resolve_path(pool, log, &ctx.jsons_root, base_dir, entry_path, &abs, err) !=
      NGX_OK) {
    yyjson_mut_doc_free(ctx.out_doc);
    return NULL;
  }

  ngx_array_t *rules = NULL;
  if (waf_collect_rules(&ctx, &abs, 0, &rules) != NGX_OK) {
    yyjson_mut_doc_free(ctx.out_doc);
    return NULL;
  }

  yyjson_mut_val *root = yyjson_mut_obj(ctx.out_doc);
  if (!root) {
    yyjson_mut_doc_free(ctx.out_doc);
    return NULL;
  }
  yyjson_mut_doc_set_root(ctx.out_doc, root);

  yyjson_mut_val *rules_arr = yyjson_mut_arr(ctx.out_doc);
  if (!rules_arr) {
    yyjson_mut_doc_free(ctx.out_doc);
    return NULL;
  }

  if (!yyjson_mut_obj_add(root, yyjson_mut_str(ctx.out_doc, "rules"), rules_arr)) {
    yyjson_mut_doc_free(ctx.out_doc);
    return NULL;
  }

  waf_rule_entry_t *entries = rules->elts;
  for (ngx_uint_t i = 0; i < rules->nelts; i++) {
    if (!yyjson_mut_arr_append(rules_arr, entries[i].rule)) {
      yyjson_mut_doc_free(ctx.out_doc);
      return NULL;
    }
  }

  /* 透传 version/meta/policies */
  ngx_http_waf_json_error_t tmp_err;
  waf_json_reset_error(&tmp_err);
  yyjson_doc *entry_doc = ngx_http_waf_json_read_single(pool, log, &abs, &tmp_err);
  if (entry_doc) {
    yyjson_val *entry_root = yyjson_doc_get_root(entry_doc);
    if (entry_root && yyjson_is_obj(entry_root)) {
      yyjson_val *version = yyjson_obj_get(entry_root, "version");
      if (version) {
        yyjson_mut_val *v = yyjson_val_mut_copy(ctx.out_doc, version);
        if (v) {
          yyjson_mut_obj_add(root, yyjson_mut_str(ctx.out_doc, "version"), v);
        }
      }
      yyjson_val *meta = yyjson_obj_get(entry_root, "meta");
      if (meta) {
        yyjson_mut_val *m = yyjson_val_mut_copy(ctx.out_doc, meta);
        if (m) {
          yyjson_mut_obj_add(root, yyjson_mut_str(ctx.out_doc, "meta"), m);
        }
      }
      yyjson_val *policies = yyjson_obj_get(entry_root, "policies");
      if (policies) {
        yyjson_mut_val *p = yyjson_val_mut_copy(ctx.out_doc, policies);
        if (p) {
          yyjson_mut_obj_add(root, yyjson_mut_str(ctx.out_doc, "policies"), p);
        }
      }
    }
    yyjson_doc_free(entry_doc);
  }

  yyjson_doc *final_doc = yyjson_mut_doc_imut_copy(ctx.out_doc, NULL);
  yyjson_mut_doc_free(ctx.out_doc);
  return final_doc;
}

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_waf_module_v2.h"
#include <yyjson/yyjson.h>

/*
 * JSON 解析与合并骨架实现
 * 说明：本文件仅提供最小可编译的桩实现，后续在 M1 中补全逻辑。
 */

/* 前置声明：用于在 resolve/join/dirname 调用统一的字符串级规范化 */
static ngx_int_t ngx_http_waf_normalize_path(ngx_pool_t* pool, ngx_str_t* path);

static ngx_int_t ngx_http_waf_resolve_path(ngx_pool_t* pool,
                                           ngx_log_t* log,
                                           const ngx_str_t* base_dir,
                                           const ngx_str_t* entry_path,
                                           ngx_str_t* out_abs)
{
    if (ngx_http_waf_join_path(pool, base_dir, entry_path, out_abs) != NGX_OK) {
        return NGX_ERROR;
    }
    /* 使用 NGINX 内置 full_name，将相对路径按 conf_prefix 展开为绝对路径 */
    if (ngx_conf_full_name((ngx_cycle_t*)ngx_cycle, out_abs, 1) != NGX_OK) {
        if (log) ngx_log_error(NGX_LOG_ERR, log, 0, "waf: ngx_conf_full_name failed: %V", out_abs);
        return NGX_ERROR;
    }
    /* 统一做一次无 I/O 的字符串级规范化，折叠重复斜杠与 /./ */
    if (ngx_http_waf_normalize_path(pool, out_abs) != NGX_OK) {
        if (log) ngx_log_error(NGX_LOG_ERR, log, 0, "waf: normalize path failed: %V", out_abs);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_waf_str_eq(const ngx_str_t* a, const ngx_str_t* b) {
    if (a == NULL || b == NULL) return 0;
    if (a->len != b->len) return 0;
    if (a->len == 0) return 1;
    return ngx_strncmp(a->data, b->data, a->len) == 0;
}

static ngx_int_t ngx_http_waf_push_path(ngx_array_t* stack, const ngx_str_t* path) {
    ngx_str_t* slot = ngx_array_push(stack);
    if (slot == NULL) return NGX_ERROR;
    *slot = *path;
    return NGX_OK;
}

static ngx_int_t ngx_http_waf_in_stack(ngx_array_t* stack, const ngx_str_t* path) {
    if (stack == NULL || path == NULL) return 0;
    ngx_uint_t i;
    ngx_str_t* el = stack->elts;
    for (i = 0; i < stack->nelts; i++) {
        if (ngx_http_waf_str_eq(&el[i], path)) return 1;
    }
    return 0;
}

/* 已改为使用 ngx_conf_full_name 做路径展开 */

/* 将路径中的重复斜杠与"/./"、结尾"/." 折叠，便于环检测使用字符串等价判断。
 * 不处理 ".."，避免与实际安全边界产生歧义。返回 NGX_OK 表示折叠成功（或无需处理）。*/
static ngx_int_t ngx_http_waf_normalize_path(ngx_pool_t* pool, ngx_str_t* path) {
    if (pool == NULL || path == NULL || path->data == NULL || path->len == 0) {
        return NGX_OK;
    }
    u_char* src = path->data;
    size_t n = path->len;
    u_char* dst = ngx_pnalloc(pool, n + 1);
    if (dst == NULL) {
        return NGX_ERROR;
    }
    size_t i = 0, di = 0;
    while (i < n) {
        if (src[i] == '/') {
            /* 折叠重复斜杠 */
            if (di == 0 || dst[di - 1] != '/') {
                dst[di++] = '/';
            }
            i++;
            /* 跳过单段 '.' */
            if (i < n && src[i] == '.') {
                if (i + 1 == n) {
                    /* 结尾 '/.' → 保留为 '/' */
                    i++;
                    continue;
                }
                if (src[i + 1] == '/') {
                    /* '/./' → '/' */
                    i += 2;
                    continue;
                }
            }
        } else {
            /* 复制常规段，直到下一个 '/' */
            do {
                dst[di++] = src[i++];
            } while (i < n && src[i] != '/');
        }
    }
    /* 去掉除根目录外的结尾 '/'（保持稳定性："/" 保留）*/
    if (di > 1 && dst[di - 1] == '/') {
        di--;
    }
    dst[di] = '\0';
    path->data = dst;
    path->len = di;
    return NGX_OK;
}

static yyjson_doc* ngx_http_waf_json_read_single(ngx_pool_t* pool,
                                                 ngx_log_t* log,
                                                 const ngx_str_t* abs_path,
                                                 ngx_http_waf_json_error_t* err)
{
    /* 基础实现：仅加载单个 JSON 文件（允许注释/尾逗号等），暂不处理 extends */
    yyjson_read_err yerr = {0};
    yyjson_read_flag flg = 0
        | YYJSON_READ_ALLOW_COMMENTS
        | YYJSON_READ_ALLOW_TRAILING_COMMAS
        | YYJSON_READ_ALLOW_INF_AND_NAN
        | YYJSON_READ_ALLOW_EXT_NUMBER
        | YYJSON_READ_ALLOW_EXT_ESCAPE
        | YYJSON_READ_ALLOW_EXT_WHITESPACE
        | YYJSON_READ_ALLOW_SINGLE_QUOTED_STR
        | YYJSON_READ_ALLOW_UNQUOTED_KEY
        ;

    /* 将 ngx_str_t 路径转换为以 \0 结尾的 C 字符串 */
    u_char* cpath = ngx_pnalloc(pool, abs_path->len + 1);
    if (cpath == NULL) {
        if (err) {
            ngx_str_set(&err->message, "内存不足");
        }
        return NULL;
    }
    ngx_memcpy(cpath, abs_path->data, abs_path->len);
    cpath[abs_path->len] = '\0';

    yyjson_doc* doc = yyjson_read_file((const char*)cpath, flg, NULL, &yerr);
    if (!doc) {
        if (err) {
            err->file = *abs_path;
            /* 构造错误信息：yyjson 错误 + 偏移位置 */
            const char* msg = yerr.msg ? yerr.msg : "yyjson 读取失败";
            size_t extra = ngx_strlen(msg) + 64;
            u_char* p = ngx_pnalloc(pool, extra);
            if (p) {
                int n = ngx_snprintf(p, extra, "%s at byte %uz", msg, (ngx_uint_t)yerr.pos) - p;
                if (n < 0) n = 0;
                err->message.data = p;
                err->message.len = (size_t)n;
            } else {
                ngx_str_set(&err->message, "yyjson 读取失败");
            }
        }
        if (log) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "waf json read failed: %V", abs_path);
        }
        return NULL;
    }

    return doc; /* 调用方在合适时机 yyjson_doc_free（后续会有统一释放策略） */
}

/* 提取目录部分 */
ngx_int_t ngx_http_waf_dirname(ngx_pool_t* pool,
                               const ngx_str_t* path,
                               ngx_str_t* out_dir)
{
    if (path == NULL || out_dir == NULL || pool == NULL) return NGX_ERROR;
    if (path->len == 0) return NGX_ERROR;
    size_t i = path->len;
    while (i > 0) {
        if (path->data[i - 1] == '/') break;
        i--;
    }
    if (i == 0) {
        /* 无斜杠：返回 "." */
        out_dir->len = 1;
        out_dir->data = ngx_pnalloc(pool, 2);
        if (out_dir->data == NULL) return NGX_ERROR;
        out_dir->data[0] = '.';
        out_dir->data[1] = '\0';
        if (ngx_http_waf_normalize_path(pool, out_dir) != NGX_OK) return NGX_ERROR;
        return NGX_OK;
    }

    /* 处理根目录 "/xxx" → 目录是 "/"；"/" → "/" */
    if (i == 1 && path->data[0] == '/') {
        out_dir->len = 1;
        out_dir->data = ngx_pnalloc(pool, 2);
        if (out_dir->data == NULL) return NGX_ERROR;
        out_dir->data[0] = '/';
        out_dir->data[1] = '\0';
        /* 根目录规范化等价为自身 */
        return NGX_OK;
    }

    out_dir->len = i - 1; /* 去掉末尾文件名 */
    out_dir->data = ngx_pnalloc(pool, out_dir->len + 1);
    if (out_dir->data == NULL) return NGX_ERROR;
    ngx_memcpy(out_dir->data, path->data, out_dir->len);
    out_dir->data[out_dir->len] = '\0';
    if (ngx_http_waf_normalize_path(pool, out_dir) != NGX_OK) return NGX_ERROR;
    return NGX_OK;
}

/* 删除未使用的递归检查桩（由合并管道的 waf_merge_extends_rec 取代） */

/* --------------------------
 * 合并管道（M1）：helpers
 * -------------------------- */

typedef enum {
    WAF_DUP_ERROR = 0,
    WAF_DUP_WARN_SKIP = 1,
    WAF_DUP_WARN_KEEP_LAST = 2
} waf_dup_policy_e;

typedef struct {
    ngx_pool_t* pool;
    ngx_log_t* log;
    ngx_array_t* stack; /* 路径去重/环检测（全局已访问集合语义） */
    ngx_http_waf_json_error_t* err;
    ngx_uint_t max_depth; /* 0 表示不限 */

    /* 裸路径根目录（通常来自 http 级 waf_jsons_dir）；len=0 表示未设置 */
    ngx_str_t jsons_root;

    /* 输出文档（可变） */
    yyjson_mut_doc* out_doc;
    yyjson_mut_val* out_root;
    yyjson_mut_val* out_rules; /* 最终规则数组 */

    /* 仅作用于“被引入工件”的禁用集合（来源：入口 JSON；v2.0 不支持 include/exclude） */
    yyjson_val* include_tags;   /* 未使用（v2.0 简化版） */
    yyjson_val* exclude_tags;   /* 未使用（v2.0 简化版） */
    yyjson_val* disable_by_id;  /* disableById?: number[] */
    yyjson_val* disable_by_tag; /* disableByTag?: string[] */

    waf_dup_policy_e dup_policy; /* duplicatePolicy */
} waf_merge_ctx_t;

static waf_dup_policy_e waf_parse_duplicate_policy_from_root(yyjson_val* root) {
    yyjson_val* meta = yyjson_obj_get(root, "meta");
    yyjson_val* dp = NULL;
    if (meta) dp = yyjson_obj_get(meta, "duplicatePolicy");
    if (!dp) dp = yyjson_obj_get(root, "duplicatePolicy");
    if (dp && yyjson_is_str(dp)) {
        const char* s = yyjson_get_str(dp);
        if (s) {
            if (ngx_strcmp(s, "warn_skip") == 0) return WAF_DUP_WARN_SKIP;
            if (ngx_strcmp(s, "warn_keep_last") == 0) return WAF_DUP_WARN_KEEP_LAST;
        }
    }
    return WAF_DUP_WARN_SKIP; /* 默认 warn_skip，保持容忍且有日志 */
}

static ngx_uint_t waf_string_in_arr(yyjson_val* arr, const char* s, size_t slen) {
    if (!arr || !yyjson_is_arr(arr) || !s) return 0;
    size_t n = yyjson_arr_size(arr);
    for (size_t i = 0; i < n; i++) {
        yyjson_val* it = yyjson_arr_get(arr, i);
        if (yyjson_is_str(it)) {
            const char* t = yyjson_get_str(it);
            if (t && ngx_strncmp(t, s, slen) == 0 && t[slen] == '\0') {
                return 1;
            }
        }
    }
    return 0;
}

static ngx_uint_t waf_id_in_arr(yyjson_val* arr, int64_t id) {
    if (!arr || !yyjson_is_arr(arr)) return 0;
    size_t n = yyjson_arr_size(arr);
    for (size_t i = 0; i < n; i++) {
        yyjson_val* it = yyjson_arr_get(arr, i);
        if (yyjson_is_int(it)) {
            if ((int64_t)yyjson_get_sint(it) == id) return 1;
        }
    }
    return 0;
}

static ngx_uint_t waf_rule_has_any_tag(yyjson_val* rule_obj, yyjson_val* tag_set) {
    if (!tag_set || !yyjson_is_arr(tag_set) || !rule_obj || !yyjson_is_obj(rule_obj)) return 0;
    yyjson_val* tags = yyjson_obj_get(rule_obj, "tags");
    if (!tags || !yyjson_is_arr(tags)) return 0;
    size_t n = yyjson_arr_size(tags);
    for (size_t i = 0; i < n; i++) {
        yyjson_val* tv = yyjson_arr_get(tags, i);
        if (yyjson_is_str(tv)) {
            const char* s = yyjson_get_str(tv);
            if (s && waf_string_in_arr(tag_set, s, ngx_strlen(s))) return 1;
        }
    }
    return 0;
}

static ngx_uint_t waf_rule_get_id(yyjson_val* rule_obj, int64_t* out_id) {
    if (!rule_obj || !yyjson_is_obj(rule_obj) || !out_id) return 0;
    yyjson_val* idv = yyjson_obj_get(rule_obj, "id");
    if (!idv || !yyjson_is_int(idv)) return 0;
    *out_id = yyjson_get_sint(idv);
    return 1;
}

static ssize_t waf_mut_rules_find_index_by_id(yyjson_mut_val* arr, int64_t id) {
    if (!arr) return -1;
    size_t n = yyjson_mut_arr_size(arr);
    for (size_t i = 0; i < n; i++) {
        yyjson_mut_val* it = yyjson_mut_arr_get(arr, i);
        if (!it) continue;
        yyjson_mut_val* idv = yyjson_mut_obj_get(it, "id");
        if (idv && yyjson_is_int((yyjson_val*)idv)) {
            if ((int64_t)yyjson_get_sint((yyjson_val*)idv) == id) return (ssize_t)i;
        }
    }
    return -1;
}

static ngx_int_t waf_append_rule_with_policy(waf_merge_ctx_t* ctx,
                                             yyjson_val* rule_from_doc,
                                             const ngx_str_t* src_path)
{
    int64_t id = 0;
    if (!waf_rule_get_id(rule_from_doc, &id)) {
        if (ctx->log) ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                                    "waf: skip rule without valid id from %V", src_path);
        return NGX_OK; /* 非致命：跳过 */
    }

    ssize_t exist = waf_mut_rules_find_index_by_id(ctx->out_rules, id);
    if (exist >= 0) {
        switch (ctx->dup_policy) {
        case WAF_DUP_ERROR: {
            if (ctx->err) {
                ctx->err->file = *src_path;
                ctx->err->json_pointer.len = 0;
                ctx->err->json_pointer.data = NULL;
                /* 构造错误信息 */
                const size_t cap = 64;
                u_char* p = ngx_pnalloc(ctx->pool, cap);
                if (p) {
                    int n = ngx_snprintf(p, cap, "重复规则 id=%L", id) - p;
                    if (n < 0) n = 0;
                    ctx->err->message.data = p;
                    ctx->err->message.len = (size_t)n;
                } else {
                    ngx_str_set(&ctx->err->message, "重复规则 id");
                }
            }
            if (ctx->log) ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                                         "waf: duplicate rule id=%L at %V (policy=error)", id, src_path);
            return NGX_ERROR;
        }
        case WAF_DUP_WARN_SKIP: {
            if (ctx->log) ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                                         "waf: duplicate rule id=%L at %V, skip (policy=warn_skip)", id, src_path);
            return NGX_OK; /* 跳过新条目 */
        }
        case WAF_DUP_WARN_KEEP_LAST: {
            yyjson_mut_val* new_val = yyjson_val_mut_copy(ctx->out_doc, rule_from_doc);
            if (new_val == NULL) {
                if (ctx->err) { ngx_str_set(&ctx->err->message, "内存不足：复制规则"); }
                return NGX_ERROR;
            }
            if (!yyjson_mut_arr_replace(ctx->out_rules, (size_t)exist, new_val)) {
                if (ctx->err) { ngx_str_set(&ctx->err->message, "写入规则失败"); }
                return NGX_ERROR;
            }
            if (ctx->log) ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                                         "waf: duplicate rule id=%L at %V, keep last (policy=warn_keep_last)", id, src_path);
            return NGX_OK;
        }
        }
    }

    yyjson_mut_val* copied = yyjson_val_mut_copy(ctx->out_doc, rule_from_doc);
    if (copied == NULL) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "内存不足：复制规则"); }
        return NGX_ERROR;
    }
    if (!yyjson_mut_arr_append(ctx->out_rules, copied)) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "写入规则失败"); }
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t waf_merge_rules_from_array(waf_merge_ctx_t* ctx,
                                            yyjson_val* rules_arr,
                                            ngx_uint_t apply_filters,
                                            const ngx_str_t* src_path)
{
    if (!rules_arr || !yyjson_is_arr(rules_arr)) return NGX_OK; /* 无规则可并入 */
    size_t n = yyjson_arr_size(rules_arr);
    for (size_t i = 0; i < n; i++) {
        yyjson_val* rule = yyjson_arr_get(rules_arr, i);
        if (!rule || !yyjson_is_obj(rule)) continue;

        if (apply_filters) {
            /* v2.0：仅支持对 imported_set 应用 disableById/disableByTag */
            int64_t id = 0;
            if (waf_rule_get_id(rule, &id)) {
                if (waf_id_in_arr(ctx->disable_by_id, id)) continue;
            }
            if (ctx->disable_by_tag && yyjson_is_arr(ctx->disable_by_tag)) {
                if (waf_rule_has_any_tag(rule, ctx->disable_by_tag)) continue;
            }
        }

        if (waf_append_rule_with_policy(ctx, rule, src_path) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_int_t waf_merge_rules_from_doc(waf_merge_ctx_t* ctx,
                                          yyjson_doc* doc,
                                          ngx_uint_t apply_filters,
                                          const ngx_str_t* src_path)
{
    if (!doc) return NGX_OK;
    yyjson_val* root = yyjson_doc_get_root(doc);
    if (!root || !yyjson_is_obj(root)) return NGX_OK;
    yyjson_val* rules = yyjson_obj_get(root, "rules");
    return waf_merge_rules_from_array(ctx, rules, apply_filters, src_path);
}

static ngx_int_t waf_merge_extends_rec(waf_merge_ctx_t* ctx,
                                       const ngx_str_t* base,
                                       const ngx_str_t* rel,
                                       ngx_uint_t depth)
{
    if (ctx->max_depth != 0 && depth > ctx->max_depth) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "extends 递归深度超出上限"); }
        return NGX_ERROR;
    }

    /* 解析 rel：绝对路径 → 直接使用；以 '.' 开头 → 相对 base；否则（裸路径）优先相对 jsons_root */
    ngx_str_t abs2;
    if (rel->len > 0 && rel->data[0] == '/') {
        abs2.len = rel->len;
        abs2.data = ngx_pnalloc(ctx->pool, abs2.len + 1);
        if (abs2.data == NULL) { if (ctx->err) { ngx_str_set(&ctx->err->message, "内存不足：abs path"); } return NGX_ERROR; }
        ngx_memcpy(abs2.data, rel->data, rel->len);
        abs2.data[abs2.len] = '\0';
    } else if (rel->len > 0 && rel->data[0] == '.') {
        if (ngx_http_waf_join_path(ctx->pool, base, rel, &abs2) != NGX_OK) {
            if (ctx->err) { ngx_str_set(&ctx->err->message, "路径解析失败"); }
            return NGX_ERROR;
        }
    } else {
        const ngx_str_t* root = (ctx->jsons_root.len > 0) ? &ctx->jsons_root : base;
        if (ngx_http_waf_join_path(ctx->pool, root, rel, &abs2) != NGX_OK) {
            if (ctx->err) { ngx_str_set(&ctx->err->message, "路径解析失败"); }
            return NGX_ERROR;
        }
    }

    /* 使用 NGINX 内置 full_name，按 conf_prefix 展开为绝对路径 */
    if (ngx_conf_full_name((ngx_cycle_t*)ngx_cycle, &abs2, 1) != NGX_OK) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "路径展开失败（ngx_conf_full_name）"); }
        return NGX_ERROR;
    }

    /* 规范化路径用于环检测的等价比较（不改变实际文件访问语义） */
    if (ngx_http_waf_normalize_path(ctx->pool, &abs2) != NGX_OK) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "路径规范化失败"); }
        return NGX_ERROR;
    }

    if (ngx_http_waf_in_stack(ctx->stack, &abs2)) {
        if (ctx->err) {
            ctx->err->file = abs2;
            ngx_str_set(&ctx->err->message, "检测到 extends 循环引用");
        }
        if (ctx->log) ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "waf json extends cycle: %V", &abs2);
        return NGX_ERROR;
    }

    size_t saved_nelts = ctx->stack->nelts;
    if (ngx_http_waf_push_path(ctx->stack, &abs2) != NGX_OK) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "内存不足：push stack"); }
        return NGX_ERROR;
    }

    yyjson_doc* doc = ngx_http_waf_json_read_single(ctx->pool, ctx->log, &abs2, ctx->err);
    if (!doc) { ctx->stack->nelts = saved_nelts; return NGX_ERROR; }

    yyjson_val* root = yyjson_doc_get_root(doc);
    yyjson_val* meta = root ? yyjson_obj_get(root, "meta") : NULL;
    yyjson_val* ext = meta ? yyjson_obj_get(meta, "extends") : NULL;
    if (ext) {
        if (!yyjson_is_arr(ext)) {
            if (ctx->err) {
                ctx->err->file = abs2;
                ngx_str_set(&ctx->err->json_pointer, "/meta/extends");
                ngx_str_set(&ctx->err->message, "字段 meta.extends 必须为数组");
            }
            yyjson_doc_free(doc);
            ctx->stack->nelts = saved_nelts;
            return NGX_ERROR;
        }
        size_t i, n = yyjson_arr_size(ext);
        for (i = 0; i < n; i++) {
            yyjson_val* it = yyjson_arr_get(ext, i);
            if (!yyjson_is_str(it)) {
                if (ctx->err) {
                    ctx->err->file = abs2;
                    ngx_str_set(&ctx->err->json_pointer, "/meta/extends[]");
                    ngx_str_set(&ctx->err->message, "meta.extends 每个元素必须为字符串路径");
                }
                yyjson_doc_free(doc);
                ctx->stack->nelts = saved_nelts;
                return NGX_ERROR;
            }
            const char* s = yyjson_get_str(it);
            size_t sl = yyjson_get_len(it);
            ngx_str_t child_rel;
            child_rel.len = sl;
            child_rel.data = ngx_pnalloc(ctx->pool, sl + 1);
            if (child_rel.data == NULL) {
                if (ctx->err) { ngx_str_set(&ctx->err->message, "内存不足：child path"); }
                yyjson_doc_free(doc);
                ctx->stack->nelts = saved_nelts;
                return NGX_ERROR;
            }
            ngx_memcpy(child_rel.data, (const u_char*)s, sl);
            child_rel.data[sl] = '\0';

            ngx_str_t cur_dir;
            if (ngx_http_waf_dirname(ctx->pool, &abs2, &cur_dir) != NGX_OK) {
                if (ctx->err) { ngx_str_set(&ctx->err->message, "dirname 失败"); }
                yyjson_doc_free(doc);
                ctx->stack->nelts = saved_nelts;
                return NGX_ERROR;
            }

            if (waf_merge_extends_rec(ctx, &cur_dir, &child_rel, depth + 1) != NGX_OK) {
                yyjson_doc_free(doc);
                ctx->stack->nelts = saved_nelts;
                return NGX_ERROR;
            }
        }
    }

    /* 并入当前工件的规则（应用 include/exclude/disable 过滤） */
    if (waf_merge_rules_from_doc(ctx, doc, /*apply_filters=*/1, &abs2) != NGX_OK) {
        yyjson_doc_free(doc);
        ctx->stack->nelts = saved_nelts;
        return NGX_ERROR;
    }

    yyjson_doc_free(doc);
    ctx->stack->nelts = saved_nelts;
    return NGX_OK;
}

yyjson_doc* ngx_http_waf_json_load_and_merge(ngx_pool_t* pool,
                                             ngx_log_t* log,
                                             const ngx_str_t* base_dir,
                                             const ngx_str_t* entry_path,
                                             ngx_uint_t max_depth,
                                             ngx_http_waf_json_error_t* err)
{
    if (err) {
        err->file.len = 0;
        err->json_pointer.len = 0;
        err->message.len = 0;
    }

    if (pool == NULL || entry_path == NULL) {
        if (err) { ngx_str_set(&err->message, "参数无效：pool 或 entry_path 为空"); }
        return NULL;
    }

    ngx_str_t abs;
    if (ngx_http_waf_resolve_path(pool, log, base_dir, entry_path, &abs) != NGX_OK) {
        if (err) { ngx_str_set(&err->message, "路径解析失败"); }
        return NULL;
    }

    /* 读取入口 JSON（用于解析自身字段与 extends 列表） */
    ngx_http_waf_json_error_t yerr_tmp = {0};
    yyjson_doc* entry_doc = ngx_http_waf_json_read_single(pool, log, &abs, &yerr_tmp);
    if (!entry_doc) {
        if (err) { *err = yerr_tmp; }
        return NULL;
    }
    yyjson_val* entry_root = yyjson_doc_get_root(entry_doc);
    if (!entry_root || !yyjson_is_obj(entry_root)) {
        if (err) { ngx_str_set(&err->message, "入口 JSON 根应为对象"); }
        yyjson_doc_free(entry_doc);
        return NULL;
    }

    /* 构建输出可变文档 */
    yyjson_mut_doc* out_doc = yyjson_mut_doc_new(NULL);
    if (!out_doc) {
        if (err) { ngx_str_set(&err->message, "内存不足：创建输出文档"); }
        yyjson_doc_free(entry_doc);
        return NULL;
    }
    yyjson_mut_val* out_root = yyjson_mut_obj(out_doc);
    if (!out_root) {
        if (err) { ngx_str_set(&err->message, "内存不足：创建根对象"); }
        yyjson_mut_doc_free(out_doc);
        yyjson_doc_free(entry_doc);
        return NULL;
    }
    yyjson_mut_doc_set_root(out_doc, out_root);
    yyjson_mut_val* out_rules = yyjson_mut_arr(out_doc);
    if (!out_rules || !yyjson_mut_obj_add_val(out_doc, out_root, "rules", out_rules)) {
        if (err) { ngx_str_set(&err->message, "内存不足：创建规则数组"); }
        yyjson_mut_doc_free(out_doc);
        yyjson_doc_free(entry_doc);
        return NULL;
    }

    /* 初始化合并上下文（过滤/禁用集合来自入口 JSON，仅作用于被引入工件） */
    waf_merge_ctx_t mctx;
    ngx_memzero(&mctx, sizeof(mctx));
    mctx.pool = pool;
    mctx.log = log;
    mctx.err = err;
    mctx.max_depth = max_depth;
    mctx.out_doc = out_doc;
    mctx.out_root = out_root;
    mctx.out_rules = out_rules;

    ngx_array_t* stack = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (!stack) {
        if (err) { ngx_str_set(&err->message, "内存不足：stack"); }
        yyjson_mut_doc_free(out_doc);
        yyjson_doc_free(entry_doc);
        return NULL;
    }
    mctx.stack = stack;

    /* 允许裸路径相对 waf_jsons_dir 解析（若 base_dir 提供） */
    if (base_dir && base_dir->len != 0) {
        mctx.jsons_root = *base_dir;
    } else {
        mctx.jsons_root.len = 0;
        mctx.jsons_root.data = NULL;
    }

    yyjson_val* meta = yyjson_obj_get(entry_root, "meta");
    /* v2.0：不支持 include/exclude，显式置空避免误用 */
    mctx.include_tags = NULL;
    mctx.exclude_tags = NULL;
    mctx.disable_by_id = yyjson_obj_get(entry_root, "disableById");
    mctx.disable_by_tag = yyjson_obj_get(entry_root, "disableByTag");
    mctx.dup_policy = waf_parse_duplicate_policy_from_root(entry_root);

    /* 先合并 extends 树（左到右），对“被引入工件”应用 include/exclude 与禁用 */
    yyjson_val* ext = meta ? yyjson_obj_get(meta, "extends") : NULL;
    if (ext) {
        if (!yyjson_is_arr(ext)) {
            if (err) {
                err->file = abs;
                ngx_str_set(&err->json_pointer, "/meta/extends");
                ngx_str_set(&err->message, "字段 meta.extends 必须为数组");
            }
            yyjson_mut_doc_free(out_doc);
            yyjson_doc_free(entry_doc);
            return NULL;
        }
        ngx_str_t entry_dir;
        if (ngx_http_waf_dirname(pool, &abs, &entry_dir) != NGX_OK) {
            if (err) { ngx_str_set(&err->message, "dirname 失败"); }
            yyjson_mut_doc_free(out_doc);
            yyjson_doc_free(entry_doc);
            return NULL;
        }
        size_t i, n = yyjson_arr_size(ext);
        for (i = 0; i < n; i++) {
            yyjson_val* it = yyjson_arr_get(ext, i);
            if (!yyjson_is_str(it)) {
                if (err) {
                    err->file = abs;
                    ngx_str_set(&err->json_pointer, "/meta/extends[]");
                    ngx_str_set(&err->message, "meta.extends 每个元素必须为字符串路径");
                }
                yyjson_mut_doc_free(out_doc);
                yyjson_doc_free(entry_doc);
                return NULL;
            }
            const char* s = yyjson_get_str(it);
            size_t sl = yyjson_get_len(it);
            ngx_str_t child_rel;
            child_rel.len = sl;
            child_rel.data = ngx_pnalloc(pool, sl + 1);
            if (child_rel.data == NULL) {
                if (err) { ngx_str_set(&err->message, "内存不足：child path"); }
                yyjson_mut_doc_free(out_doc);
                yyjson_doc_free(entry_doc);
                return NULL;
            }
            ngx_memcpy(child_rel.data, (const u_char*)s, sl);
            child_rel.data[sl] = '\0';

            if (waf_merge_extends_rec(&mctx, &entry_dir, &child_rel, 1) != NGX_OK) {
                yyjson_mut_doc_free(out_doc);
                yyjson_doc_free(entry_doc);
                return NULL;
            }
        }
    }

    /* 复制入口 JSON 的 version（若有）与 policies（若有）到输出根，保持“功能不失” */
    yyjson_val* entry_version = yyjson_obj_get(entry_root, "version");
    if (entry_version) {
        yyjson_mut_val* v = yyjson_val_mut_copy(out_doc, entry_version);
        if (!v || !yyjson_mut_obj_add_val(out_doc, out_root, "version", v)) {
            if (err) { ngx_str_set(&err->message, "内存不足：复制 version"); }
            yyjson_mut_doc_free(out_doc);
            yyjson_doc_free(entry_doc);
            return NULL;
        }
    }
    yyjson_val* entry_policies = yyjson_obj_get(entry_root, "policies");
    if (entry_policies && yyjson_is_obj(entry_policies)) {
        yyjson_mut_val* p = yyjson_val_mut_copy(out_doc, entry_policies);
        if (!p || !yyjson_mut_obj_add_val(out_doc, out_root, "policies", p)) {
            if (err) { ngx_str_set(&err->message, "内存不足：复制 policies"); }
            yyjson_mut_doc_free(out_doc);
            yyjson_doc_free(entry_doc);
            return NULL;
        }
    }

    /* 再追加入口文件自身的 rules（不做禁用过滤） */
    if (waf_merge_rules_from_doc(&mctx, entry_doc, /*apply_filters=*/0, &abs) != NGX_OK) {
        yyjson_mut_doc_free(out_doc);
        yyjson_doc_free(entry_doc);
        return NULL;
    }


    /* 产出只读文档并清理可变文档 */
    yyjson_doc* final_doc = yyjson_mut_doc_imut_copy(out_doc, NULL);
    yyjson_mut_doc_free(out_doc);
    yyjson_doc_free(entry_doc);
    return final_doc;
}

ngx_int_t ngx_http_waf_join_path(ngx_pool_t* pool,
                                 const ngx_str_t* base_dir,
                                 const ngx_str_t* path,
                                 ngx_str_t* out_abs)
{
    if (out_abs == NULL || path == NULL || pool == NULL) {
        return NGX_ERROR;
    }

    /* 简化：若 path 为绝对路径，直接返回；否则按 base_dir 拼接 */
    if (path->len > 0 && ((const char*)path->data)[0] == '/') {
        out_abs->len = path->len;
        out_abs->data = ngx_pnalloc(pool, out_abs->len + 1);
        if (out_abs->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(out_abs->data, path->data, path->len);
        out_abs->data[out_abs->len] = '\0';
        if (ngx_http_waf_normalize_path(pool, out_abs) != NGX_OK) return NGX_ERROR;
        return NGX_OK;
    }

    if (base_dir == NULL || base_dir->len == 0) {
        /* 无 base_dir 则按原样返回（Nginx 会按 prefix 解析） */
        out_abs->len = path->len;
        out_abs->data = ngx_pnalloc(pool, out_abs->len + 1);
        if (out_abs->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(out_abs->data, path->data, path->len);
        out_abs->data[out_abs->len] = '\0';
        if (ngx_http_waf_normalize_path(pool, out_abs) != NGX_OK) return NGX_ERROR;
        return NGX_OK;
    }

    size_t len = base_dir->len + 1 /*slash*/ + path->len;
    u_char* p = ngx_pnalloc(pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, base_dir->data, base_dir->len);
    p[base_dir->len] = '/';
    ngx_memcpy(p + base_dir->len + 1, path->data, path->len);
    p[len] = '\0';

    out_abs->data = p;
    out_abs->len = len;
    if (ngx_http_waf_normalize_path(pool, out_abs) != NGX_OK) return NGX_ERROR;
    return NGX_OK;
}




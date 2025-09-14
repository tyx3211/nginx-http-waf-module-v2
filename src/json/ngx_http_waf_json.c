#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_waf_module_v2.h"
#include <yyjson/yyjson.h>

/*
 * JSON 解析与合并骨架实现
 * 说明：本文件仅提供最小可编译的桩实现，后续在 M1 中补全逻辑。
 */

static ngx_int_t ngx_http_waf_resolve_path(ngx_pool_t* pool,
                                           ngx_log_t* log,
                                           const ngx_str_t* base_dir,
                                           const ngx_str_t* entry_path,
                                           ngx_str_t* out_abs)
{
    (void)log;
    return ngx_http_waf_join_path(pool, base_dir, entry_path, out_abs);
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
        /* 无斜杠，返回当前目录 "." */
        const char* dot = ".";
        out_dir->len = 1;
        out_dir->data = ngx_pnalloc(pool, 2);
        if (out_dir->data == NULL) return NGX_ERROR;
        out_dir->data[0] = dot[0];
        out_dir->data[1] = '\0';
        return NGX_OK;
    }
    out_dir->len = i - 1; /* 去掉末尾斜杠前的部分长度 */
    out_dir->data = ngx_pnalloc(pool, out_dir->len + 1);
    if (out_dir->data == NULL) return NGX_ERROR;
    ngx_memcpy(out_dir->data, path->data, out_dir->len);
    out_dir->data[out_dir->len] = '\0';
    return NGX_OK;
}

/* 递归上下文（文件作用域） */
typedef struct {
    ngx_pool_t* pool;
    ngx_log_t* log;
    ngx_array_t* stack;
    ngx_http_waf_json_error_t* err;
    ngx_uint_t max_depth; /* 0 表示不限 */
} waf_ctx_t;

static yyjson_doc* waf_load_rec(waf_ctx_t* ctx,
                                const ngx_str_t* base,
                                const ngx_str_t* path,
                                ngx_uint_t depth);

static yyjson_doc* waf_load_rec(waf_ctx_t* ctx,
                                const ngx_str_t* base,
                                const ngx_str_t* path,
                                ngx_uint_t depth)
{
    if (ctx->max_depth != 0 && depth > ctx->max_depth) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "extends 递归深度超出上限"); }
        return NULL;
    }

    ngx_str_t abs2;
    if (ngx_http_waf_join_path(ctx->pool, base, path, &abs2) != NGX_OK) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "路径解析失败"); }
        return NULL;
    }

    if (ngx_http_waf_in_stack(ctx->stack, &abs2)) {
        if (ctx->err) {
            ctx->err->file = abs2;
            ngx_str_set(&ctx->err->message, "检测到 extends 循环引用");
        }
        if (ctx->log) ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "waf json extends cycle: %V", &abs2);
        return NULL;
    }

    if (ngx_http_waf_push_path(ctx->stack, &abs2) != NGX_OK) {
        if (ctx->err) { ngx_str_set(&ctx->err->message, "内存不足：push stack"); }
        return NULL;
    }

    yyjson_doc* doc = ngx_http_waf_json_read_single(ctx->pool, ctx->log, &abs2, ctx->err);
    if (!doc) return NULL;

    /* 递归检查子 extends */
    yyjson_val* root = yyjson_doc_get_root(doc);
    yyjson_val* meta = yyjson_obj_get(root, "meta");
    yyjson_val* ext = meta ? yyjson_obj_get(meta, "extends") : NULL;
    if (ext) {
        if (!yyjson_is_arr(ext)) {
            if (ctx->err) {
                ctx->err->file = abs2;
                ngx_str_set(&ctx->err->json_pointer, "/meta/extends");
                ngx_str_set(&ctx->err->message, "字段 meta.extends 必须为数组");
            }
            yyjson_doc_free(doc);
            return NULL;
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
                return NULL;
            }
            const char* s = yyjson_get_str(it);
            size_t sl = yyjson_get_len(it);
            ngx_str_t child_rel;
            child_rel.len = sl;
            child_rel.data = ngx_pnalloc(ctx->pool, sl + 1);
            if (child_rel.data == NULL) {
                if (ctx->err) { ngx_str_set(&ctx->err->message, "内存不足：child path"); }
                yyjson_doc_free(doc);
                return NULL;
            }
            ngx_memcpy(child_rel.data, (const u_char*)s, sl);
            child_rel.data[sl] = '\0';

            ngx_str_t cur_dir;
            if (ngx_http_waf_dirname(ctx->pool, &abs2, &cur_dir) != NGX_OK) {
                if (ctx->err) { ngx_str_set(&ctx->err->message, "dirname 失败"); }
                yyjson_doc_free(doc);
                return NULL;
            }

            yyjson_doc* sub = waf_load_rec(ctx, &cur_dir, &child_rel, depth + 1);
            if (!sub) {
                yyjson_doc_free(doc);
                return NULL;
            }
            /* 暂不合并，仅校验；避免泄漏 */
            yyjson_doc_free(sub);
        }
    }

    return doc;
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
        if (err) {
            ngx_str_set(&err->message, "参数无效：pool 或 entry_path 为空");
        }
        return NULL;
    }

    ngx_str_t abs;
    if (ngx_http_waf_resolve_path(pool, log, base_dir, entry_path, &abs) != NGX_OK) {
        if (err) {
            ngx_str_set(&err->message, "路径解析失败");
        }
        return NULL;
    }

    /* 递归加载与循环/深度检测（暂不合并规则，仅验证加载有效性） */
    ngx_array_t* stack = ngx_array_create(pool, 4, sizeof(ngx_str_t));
    if (stack == NULL) {
        if (err) { ngx_str_set(&err->message, "内存不足：stack"); }
        return NULL;
    }

    waf_ctx_t wctx = { pool, log, stack, err, max_depth };
    ngx_str_t empty_base = { 0, NULL };
    yyjson_doc* res = waf_load_rec(&wctx, base_dir ? base_dir : &empty_base, &entry_path[0], 1);
    return res;
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
    return NGX_OK;
}



#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_waf_compiler.h"

#include <ngx_regex.h>
#include <uthash/uthash.h>
#include <yyjson/yyjson.h>

/*
 * M2：编译期快照最小实现
 *
 * 目标：将 M1 产出的合并文档（只读
 * yyjson_doc）编译为可被运行期直接消费的只读快照。 本文件实现最小可用集：
 *  - 遍历最终 rules 数组，将每条规则转为 waf_compiled_rule_t
 *  - 仅做基础类型/取值校验（假定 M1 已保证 targets/HEADER/ALL_PARAMS 等）
 *  - 暂不做 REGEX/CIDR 的预编译与分桶；留待 M2 后续步骤
 */

/* ------------------------ 工具：字符串复制 ------------------------ */
static ngx_int_t waf_copy_str(ngx_pool_t *pool, const char *s, size_t len, ngx_str_t *out)
{
  if (s == NULL || len == 0) {
    out->data = NULL;
    out->len = 0;
    return NGX_OK;
  }
  u_char *p = ngx_pnalloc(pool, len);
  if (p == NULL)
    return NGX_ERROR;
  ngx_memcpy(p, s, len);
  out->data = p;
  out->len = len;
  return NGX_OK;
}

/* ------------------------ 工具：枚举解析 ------------------------ */
static ngx_int_t waf_parse_match(const char *s, size_t len, waf_match_e *out)
{
  if (len == 8 && ngx_strncasecmp((u_char *)s, (u_char *)"CONTAINS", 8) == 0) {
    *out = WAF_MATCH_CONTAINS;
    return NGX_OK;
  }
  if (len == 5 && ngx_strncasecmp((u_char *)s, (u_char *)"EXACT", 5) == 0) {
    *out = WAF_MATCH_EXACT;
    return NGX_OK;
  }
  if (len == 5 && ngx_strncasecmp((u_char *)s, (u_char *)"REGEX", 5) == 0) {
    *out = WAF_MATCH_REGEX;
    return NGX_OK;
  }
  if (len == 4 && ngx_strncasecmp((u_char *)s, (u_char *)"CIDR", 4) == 0) {
    *out = WAF_MATCH_CIDR;
    return NGX_OK;
  }
  return NGX_ERROR;
}

static ngx_int_t waf_parse_action(const char *s, size_t len, waf_action_e *out)
{
  if (len == 4 && ngx_strncasecmp((u_char *)s, (u_char *)"DENY", 4) == 0) {
    *out = WAF_ACT_DENY;
    return NGX_OK;
  }
  if (len == 3 && ngx_strncasecmp((u_char *)s, (u_char *)"LOG", 3) == 0) {
    *out = WAF_ACT_LOG;
    return NGX_OK;
  }
  if (len == 6 && ngx_strncasecmp((u_char *)s, (u_char *)"BYPASS", 6) == 0) {
    *out = WAF_ACT_BYPASS;
    return NGX_OK;
  }
  return NGX_ERROR;
}

static ngx_int_t waf_parse_target(const char *s, size_t len, waf_target_e *out)
{
  /* M1 已将 ALL_PARAMS 展开；此处不处理 ALL_PARAMS */
  if (len == 9 && ngx_strncasecmp((u_char *)s, (u_char *)"CLIENT_IP", 9) == 0) {
    *out = WAF_T_CLIENT_IP;
    return NGX_OK;
  }
  if (len == 3 && ngx_strncasecmp((u_char *)s, (u_char *)"URI", 3) == 0) {
    *out = WAF_T_URI;
    return NGX_OK;
  }
  /* 注意："ARGS_COMBINED" 长度为 13 */
  if (len == 13 && ngx_strncasecmp((u_char *)s, (u_char *)"ARGS_COMBINED", 13) == 0) {
    *out = WAF_T_ARGS_COMBINED;
    return NGX_OK;
  }
  if (len == 9 && ngx_strncasecmp((u_char *)s, (u_char *)"ARGS_NAME", 9) == 0) {
    *out = WAF_T_ARGS_NAME;
    return NGX_OK;
  }
  if (len == 10 && ngx_strncasecmp((u_char *)s, (u_char *)"ARGS_VALUE", 10) == 0) {
    *out = WAF_T_ARGS_VALUE;
    return NGX_OK;
  }
  if (len == 4 && ngx_strncasecmp((u_char *)s, (u_char *)"BODY", 4) == 0) {
    *out = WAF_T_BODY;
    return NGX_OK;
  }
  if (len == 6 && ngx_strncasecmp((u_char *)s, (u_char *)"HEADER", 6) == 0) {
    *out = WAF_T_HEADER;
    return NGX_OK;
  }
  return NGX_ERROR;
}

/* ------------------------ 工具：tags 数组复制 ------------------------ */
static ngx_int_t waf_copy_tags(ngx_pool_t *pool, yyjson_val *tags_node, ngx_array_t **out_tags)
{
  if (tags_node == NULL) {
    *out_tags = NULL;
    return NGX_OK;
  }
  if (!yyjson_is_arr(tags_node))
    return NGX_ERROR;
  size_t n = yyjson_arr_size(tags_node);
  ngx_array_t *arr = ngx_array_create(pool, n > 0 ? n : 1, sizeof(ngx_str_t));
  if (arr == NULL)
    return NGX_ERROR;
  for (size_t i = 0; i < n; i++) {
    yyjson_val *it = yyjson_arr_get(tags_node, i);
    if (!yyjson_is_str(it))
      return NGX_ERROR;
    const char *s = yyjson_get_str(it);
    size_t len = yyjson_get_len(it);
    ngx_str_t *slot = ngx_array_push(arr);
    if (slot == NULL)
      return NGX_ERROR;
    if (waf_copy_str(pool, s, len, slot) != NGX_OK)
      return NGX_ERROR;
  }
  *out_tags = arr;
  return NGX_OK;
}

/* ------------------------ 工具：pattern 复制（string|string[] → array）
 * ------------------------ */
static ngx_int_t waf_copy_patterns(ngx_pool_t *pool, yyjson_val *pattern_node,
                                   ngx_array_t **out_patterns)
{
  ngx_array_t *arr = ngx_array_create(pool, 1, sizeof(ngx_str_t));
  if (arr == NULL)
    return NGX_ERROR;

  if (yyjson_is_str(pattern_node)) {
    const char *s = yyjson_get_str(pattern_node);
    size_t len = yyjson_get_len(pattern_node);
    if (len == 0)
      return NGX_ERROR;
    ngx_str_t *slot = ngx_array_push(arr);
    if (slot == NULL)
      return NGX_ERROR;
    if (waf_copy_str(pool, s, len, slot) != NGX_OK)
      return NGX_ERROR;
  } else if (yyjson_is_arr(pattern_node)) {
    size_t n = yyjson_arr_size(pattern_node);
    if (n == 0)
      return NGX_ERROR;
    for (size_t i = 0; i < n; i++) {
      yyjson_val *it = yyjson_arr_get(pattern_node, i);
      if (!yyjson_is_str(it))
        return NGX_ERROR;
      const char *s = yyjson_get_str(it);
      size_t len = yyjson_get_len(it);
      if (len == 0)
        return NGX_ERROR;
      ngx_str_t *slot = ngx_array_push(arr);
      if (slot == NULL)
        return NGX_ERROR;
      if (waf_copy_str(pool, s, len, slot) != NGX_OK)
        return NGX_ERROR;
    }
  } else {
    return NGX_ERROR;
  }

  *out_patterns = arr;
  return NGX_OK;
}

static ngx_int_t waf_infer_phase(const waf_compiled_rule_t *r, ngx_log_t *log,
                                 ngx_http_waf_json_error_t *err)
{
  (void)log;
  /* 若 JSON 显式存在 phase（M2 最小实现暂未读取），此处可覆盖。当前按
   * target+action 推断：
   * - CLIENT_IP + BYPASS => IP_ALLOW
   * - CLIENT_IP + DENY   => IP_BLOCK
   * - URI + BYPASS       => URI_ALLOW
   * - 其他                => DETECT
   */
  if (r->target == WAF_T_CLIENT_IP && r->action == WAF_ACT_BYPASS)
    return (r->phase == 0 ? (waf_phase_e)WAF_PHASE_IP_ALLOW : r->phase);
  if (r->target == WAF_T_CLIENT_IP && r->action == WAF_ACT_DENY)
    return (r->phase == 0 ? (waf_phase_e)WAF_PHASE_IP_BLOCK : r->phase);
  if (r->target == WAF_T_URI && r->action == WAF_ACT_BYPASS)
    return (r->phase == 0 ? (waf_phase_e)WAF_PHASE_URI_ALLOW : r->phase);
  return (r->phase == 0 ? (waf_phase_e)WAF_PHASE_DETECT : r->phase);
}

static ngx_int_t waf_parse_phase_text_ci(const char *s, size_t len, waf_phase_e *out)
{
  if (len == 8 && ngx_strncasecmp((u_char *)s, (u_char *)"ip_allow", 8) == 0) {
    *out = WAF_PHASE_IP_ALLOW;
    return NGX_OK;
  }
  if (len == 8 && ngx_strncasecmp((u_char *)s, (u_char *)"ip_block", 8) == 0) {
    *out = WAF_PHASE_IP_BLOCK;
    return NGX_OK;
  }
  if (len == 9 && ngx_strncasecmp((u_char *)s, (u_char *)"uri_allow", 9) == 0) {
    *out = WAF_PHASE_URI_ALLOW;
    return NGX_OK;
  }
  if (len == 6 && ngx_strncasecmp((u_char *)s, (u_char *)"detect", 6) == 0) {
    *out = WAF_PHASE_DETECT;
    return NGX_OK;
  }
  return NGX_ERROR;
}

static ngx_int_t waf_validate_phase_combo(waf_phase_e phase, waf_target_e target,
                                          waf_action_e action)
{
  switch (phase) {
    case WAF_PHASE_IP_ALLOW:
      return (target == WAF_T_CLIENT_IP && action == WAF_ACT_BYPASS) ? NGX_OK : NGX_ERROR;
    case WAF_PHASE_IP_BLOCK:
      return (target == WAF_T_CLIENT_IP && action == WAF_ACT_DENY) ? NGX_OK : NGX_ERROR;
    case WAF_PHASE_URI_ALLOW:
      return (target == WAF_T_URI && action == WAF_ACT_BYPASS) ? NGX_OK : NGX_ERROR;
    case WAF_PHASE_DETECT:
      return NGX_OK;
    default:
      return NGX_ERROR;
  }
}

static ngx_int_t waf_bucket_append(ngx_pool_t *pool, waf_compiled_snapshot_t *snap,
                                   waf_phase_e phase, waf_target_e target,
                                   waf_compiled_rule_t *rule)
{
  ngx_array_t **slot = &snap->buckets[phase][target];
  if (*slot == NULL) {
    *slot = ngx_array_create(pool, 1, sizeof(waf_compiled_rule_t *));
    if (*slot == NULL)
      return NGX_ERROR;
  }
  waf_compiled_rule_t **p = ngx_array_push(*slot);
  if (p == NULL)
    return NGX_ERROR;
  *p = rule;
  return NGX_OK;
}

/* 稳定排序：按 priority 升序对桶内规则指针进行就地插入排序 */
static void waf_sort_bucket_by_priority_stable(ngx_array_t *bucket)
{
  if (bucket == NULL || bucket->nelts <= 1)
    return;
  waf_compiled_rule_t **items = bucket->elts;
  for (ngx_uint_t i = 1; i < bucket->nelts; i++) {
    waf_compiled_rule_t *key = items[i];
    ngx_int_t key_priority = key->priority;
    ngx_int_t j = (ngx_int_t)i - 1;
    while (j >= 0 && items[j]->priority > key_priority) {
      items[j + 1] = items[j];
      j--;
    }
    items[j + 1] = key;
  }
}

/* ------------------------ 预编译：REGEX/CIDR ------------------------ */
static ngx_int_t waf_precompile_regexes(ngx_pool_t *pool, ngx_log_t *log, waf_compiled_rule_t *rule)
{
  if (rule->match != WAF_MATCH_REGEX)
    return NGX_OK;
  ngx_uint_t n = rule->patterns ? rule->patterns->nelts : 0;
  if (n == 0)
    return NGX_OK;

  rule->compiled_regexes = ngx_array_create(pool, n, sizeof(ngx_regex_t *));
  if (rule->compiled_regexes == NULL)
    return NGX_ERROR;

  ngx_str_t *pats = rule->patterns->elts;
  for (ngx_uint_t i = 0; i < n; i++) {
    ngx_regex_compile_t rc;
    u_char errstr[256];
    ngx_memzero(&rc, sizeof(rc));
    rc.pattern = pats[i];
    rc.pool = pool;
    rc.err.len = 0;
    rc.err.data = errstr;
    rc.options = rule->caseless ? NGX_REGEX_CASELESS : 0;
    if (ngx_regex_compile(&rc) != NGX_OK) {
      if (log) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "waf: regex compile failed: id=%ui pattern=%V err=%V",
                      rule->id, &pats[i], &rc.err);
      }
      return NGX_ERROR;
    }
    ngx_regex_t **slot = ngx_array_push(rule->compiled_regexes);
    if (slot == NULL)
      return NGX_ERROR;
    *slot = rc.regex;
  }
  return NGX_OK;
}

static ngx_int_t waf_parse_cidr_one(ngx_str_t *s, ngx_cidr_t *out)
{
  ngx_memzero(out, sizeof(*out));
  if (ngx_ptocidr(s, out) != NGX_OK) {
    return NGX_ERROR;
  }
  return NGX_OK;
}

static ngx_int_t waf_precompile_cidrs(ngx_pool_t *pool, ngx_log_t *log, waf_compiled_rule_t *rule)
{
  (void)log;
  if (rule->match != WAF_MATCH_CIDR)
    return NGX_OK;
  ngx_uint_t n = rule->patterns ? rule->patterns->nelts : 0;
  if (n == 0)
    return NGX_OK;

  rule->compiled_cidrs = ngx_array_create(pool, n, sizeof(ngx_cidr_t));
  if (rule->compiled_cidrs == NULL)
    return NGX_ERROR;

  ngx_str_t *pats = rule->patterns->elts;
  for (ngx_uint_t i = 0; i < n; i++) {
    ngx_cidr_t *slot = ngx_array_push(rule->compiled_cidrs);
    if (slot == NULL)
      return NGX_ERROR;
    if (waf_parse_cidr_one(&pats[i], slot) != NGX_OK) {
      return NGX_ERROR;
    }
  }
  return NGX_OK;
}

/* ------------------------ 主编译入口 ------------------------ */
ngx_int_t ngx_http_waf_compile_rules(ngx_pool_t *pool, ngx_log_t *log, yyjson_doc *merged_doc,
                                     waf_compiled_snapshot_t **out, ngx_http_waf_json_error_t *err)
{
  if (out == NULL)
    return NGX_ERROR;
  *out = NULL;

  if (merged_doc == NULL) {
    if (err) {
      err->file.len = 0;
      err->file.data = NULL;
      err->json_pointer.len = 0;
      err->json_pointer.data = NULL;
      ngx_str_set(&err->message, "输入文档为空");
    }
    return NGX_ERROR;
  }

  yyjson_val *root = yyjson_doc_get_root(merged_doc);
  if (!root || !yyjson_is_obj(root)) {
    if (err) {
      err->file.len = 0;
      err->file.data = NULL;
      err->json_pointer.len = 0;
      err->json_pointer.data = NULL;
      ngx_str_set(&err->message, "最终文档根必须为对象");
    }
    return NGX_ERROR;
  }

  yyjson_val *rules = yyjson_obj_get(root, "rules");
  if (!rules || !yyjson_is_arr(rules)) {
    if (err) {
      err->file.len = 0;
      err->file.data = NULL;
      err->json_pointer.len = 0;
      err->json_pointer.data = NULL;
      ngx_str_set(&err->message, "最终文档缺少 rules 数组");
    }
    return NGX_ERROR;
  }

  waf_compiled_snapshot_t *snap = ngx_pcalloc(pool, sizeof(*snap));
  if (snap == NULL)
    return NGX_ERROR;
  snap->pool = pool;
  snap->all_rules = ngx_array_create(pool, yyjson_arr_size(rules) > 0 ? yyjson_arr_size(rules) : 1,
                                     sizeof(waf_compiled_rule_t));
  if (snap->all_rules == NULL)
    return NGX_ERROR;

  /* 临时：ID 唯一性校验（uthash） */
  typedef struct {
    ngx_uint_t id;
    UT_hash_handle hh;
  } waf_id_entry_t;
  waf_id_entry_t *id_map = NULL;

  size_t rn = yyjson_arr_size(rules);
  for (size_t i = 0; i < rn; i++) {
    yyjson_val *r = yyjson_arr_get(rules, i);
    if (!yyjson_is_obj(r)) {
      if (err) {
        err->file.len = 0;
        err->file.data = NULL;
        err->json_pointer.len = 0;
        err->json_pointer.data = NULL;
        ngx_str_set(&err->message, "rules[] 内部必须为对象");
      }
      return NGX_ERROR;
    }

    yyjson_val *id_node = yyjson_obj_get(r, "id");
    yyjson_val *target_node = yyjson_obj_get(r, "target");
    yyjson_val *match_node = yyjson_obj_get(r, "match");
    yyjson_val *pattern_node = yyjson_obj_get(r, "pattern");
    yyjson_val *action_node = yyjson_obj_get(r, "action");

    if (!id_node || !yyjson_is_int(id_node) || !target_node || !match_node || !pattern_node ||
        !action_node) {
      if (err) {
        err->file.len = 0;
        err->file.data = NULL;
        err->json_pointer.len = 0;
        err->json_pointer.data = NULL;
        ngx_str_set(&err->message, "规则缺少必填字段");
      }
      return NGX_ERROR;
    }

    waf_compiled_rule_t rule;
    ngx_memzero(&rule, sizeof(rule));
    rule.id = (ngx_uint_t)yyjson_get_sint(id_node);

    /* ID 唯一性：编译期再次校验，避免残余重复 */
    {
      waf_id_entry_t *found = NULL;
      HASH_FIND(hh, id_map, &rule.id, sizeof(rule.id), found);
      if (found != NULL) {
        if (err) {
          ngx_str_set(&err->message, "检测到重复的规则 id");
        }
        /* 释放 uthash 表（仅释放表结构；元素使用 pool 分配无需单独释放） */
        HASH_CLEAR(hh, id_map);
        return NGX_ERROR;
      }
      waf_id_entry_t *e = ngx_pcalloc(pool, sizeof(waf_id_entry_t));
      if (e == NULL) {
        HASH_CLEAR(hh, id_map);
        return NGX_ERROR;
      }
      e->id = rule.id;
      HASH_ADD(hh, id_map, id, sizeof(e->id), e);
    }

    /* target: M1 已保证为字符串（单目标）或字符串数组（多目标）的规范化形态。
     * M2 最小实现：若是数组，拆成多条规则；若是字符串，转 1 条。
     */
    if (yyjson_is_arr(target_node)) {
      size_t tn = yyjson_arr_size(target_node);
      if (tn == 0) {
        if (err) {
          ngx_str_set(&err->message, "target 数组不能为空");
        }
        return NGX_ERROR;
      }
      for (size_t ti = 0; ti < tn; ti++) {
        yyjson_val *t = yyjson_arr_get(target_node, ti);
        if (!yyjson_is_str(t)) {
          if (err) {
            ngx_str_set(&err->message, "target 数组元素必须为字符串");
          }
          return NGX_ERROR;
        }
        const char *ts = yyjson_get_str(t);
        size_t tl = yyjson_get_len(t);
        waf_target_e tcode;
        if (waf_parse_target(ts, tl, &tcode) != NGX_OK) {
          if (err) {
            ngx_str_set(&err->message, "未知的 target 值");
          }
          return NGX_ERROR;
        }

        waf_compiled_rule_t tmp = rule; /* 基于 id 等共性拷贝 */
        tmp.target = tcode;

        /* headerName：仅当 target=HEADER 时读取 */
        if (tcode == WAF_T_HEADER) {
          yyjson_val *hn = yyjson_obj_get(r, "headerName");
          if (!hn || !yyjson_is_str(hn) || yyjson_get_len(hn) == 0) {
            if (err) {
              ngx_str_set(&err->message, "HEADER 目标必须提供非空 headerName");
            }
            return NGX_ERROR;
          }
          if (waf_copy_str(pool, yyjson_get_str(hn), yyjson_get_len(hn), &tmp.header_name) !=
              NGX_OK)
            return NGX_ERROR;
        }

        /* match */
        {
          const char *ms = yyjson_get_str(match_node);
          size_t ml = yyjson_get_len(match_node);
          if (waf_parse_match(ms, ml, &tmp.match) != NGX_OK) {
            if (err) {
              ngx_str_set(&err->message, "非法 match 值");
            }
            return NGX_ERROR;
          }
        }

        /* pattern → patterns[] */
        if (waf_copy_patterns(pool, pattern_node, &tmp.patterns) != NGX_OK) {
          if (err) {
            ngx_str_set(&err->message, "pattern 非法或为空");
          }
          return NGX_ERROR;
        }

        /* caseless */
        {
          yyjson_val *cs = yyjson_obj_get(r, "caseless");
          tmp.caseless = (cs && yyjson_is_bool(cs)) ? (yyjson_get_bool(cs) ? 1 : 0) : 0;
        }

        /* negate */
        {
          yyjson_val *ng = yyjson_obj_get(r, "negate");
          tmp.negate = (ng && yyjson_is_bool(ng)) ? (yyjson_get_bool(ng) ? 1 : 0) : 0;
        }

        /* action */
        {
          const char *as = yyjson_get_str(action_node);
          size_t al = yyjson_get_len(action_node);
          if (waf_parse_action(as, al, &tmp.action) != NGX_OK) {
            if (err) {
              ngx_str_set(&err->message, "非法 action 值");
            }
            return NGX_ERROR;
          }
        }

        /* score/priority */
        {
          yyjson_val *sc = yyjson_obj_get(r, "score");
          yyjson_val *pr = yyjson_obj_get(r, "priority");
          tmp.score = (sc && yyjson_is_num(sc)) ? (ngx_int_t)yyjson_get_sint(sc) : 10;
          tmp.priority = (pr && yyjson_is_num(pr)) ? (ngx_int_t)yyjson_get_sint(pr) : 0;
        }

        /* tags[] */
        if (waf_copy_tags(pool, yyjson_obj_get(r, "tags"), &tmp.tags) != NGX_OK) {
          if (err) {
            ngx_str_set(&err->message, "tags 必须为字符串数组");
          }
          return NGX_ERROR;
        }

        /* phase：显式覆盖或推断，并校验组合 */
        {
          yyjson_val *ph = yyjson_obj_get(r, "phase");
          if (ph && yyjson_is_str(ph)) {
            waf_phase_e phv;
            if (waf_parse_phase_text_ci(yyjson_get_str(ph), yyjson_get_len(ph), &phv) != NGX_OK) {
              if (err) {
                ngx_str_set(&err->message, "phase 取值非法");
              }
              return NGX_ERROR;
            }
            tmp.phase = phv;
          } else {
            tmp.phase = waf_infer_phase(&tmp, log, err);
          }
          if (waf_validate_phase_combo(tmp.phase, tmp.target, tmp.action) != NGX_OK) {
            if (err) {
              ngx_str_set(&err->message, "phase/target/action 组合非法");
            }
            return NGX_ERROR;
          }
        }

        /* 追加到快照数组 */
        waf_compiled_rule_t *slot = ngx_array_push(snap->all_rules);
        if (slot == NULL)
          return NGX_ERROR;
        *slot = tmp;

        /* 分桶索引：保存指针 */
        if (waf_bucket_append(pool, snap, slot->phase, slot->target, slot) != NGX_OK)
          return NGX_ERROR;

        /* 预编译 REGEX/CIDR */
        if (waf_precompile_regexes(pool, log, slot) != NGX_OK)
          return NGX_ERROR;
        if (waf_precompile_cidrs(pool, log, slot) != NGX_OK)
          return NGX_ERROR;
      }
    } else if (yyjson_is_str(target_node)) {
      const char *ts = yyjson_get_str(target_node);
      size_t tl = yyjson_get_len(target_node);
      if (waf_parse_target(ts, tl, &rule.target) != NGX_OK) {
        if (err) {
          ngx_str_set(&err->message, "未知的 target 值");
        }
        return NGX_ERROR;
      }
      if (rule.target == WAF_T_HEADER) {
        yyjson_val *hn = yyjson_obj_get(r, "headerName");
        if (!hn || !yyjson_is_str(hn) || yyjson_get_len(hn) == 0) {
          if (err) {
            ngx_str_set(&err->message, "HEADER 目标必须提供非空 headerName");
          }
          return NGX_ERROR;
        }
        if (waf_copy_str(pool, yyjson_get_str(hn), yyjson_get_len(hn), &rule.header_name) != NGX_OK)
          return NGX_ERROR;
      }

      /* match */
      {
        const char *ms = yyjson_get_str(match_node);
        size_t ml = yyjson_get_len(match_node);
        if (waf_parse_match(ms, ml, &rule.match) != NGX_OK) {
          if (err) {
            ngx_str_set(&err->message, "非法 match 值");
          }
          return NGX_ERROR;
        }
      }

      /* pattern → patterns[] */
      if (waf_copy_patterns(pool, pattern_node, &rule.patterns) != NGX_OK) {
        if (err) {
          ngx_str_set(&err->message, "pattern 非法或为空");
        }
        return NGX_ERROR;
      }

      /* caseless */
      {
        yyjson_val *cs = yyjson_obj_get(r, "caseless");
        rule.caseless = (cs && yyjson_is_bool(cs)) ? (yyjson_get_bool(cs) ? 1 : 0) : 0;
      }

      /* negate */
      {
        yyjson_val *ng = yyjson_obj_get(r, "negate");
        rule.negate = (ng && yyjson_is_bool(ng)) ? (yyjson_get_bool(ng) ? 1 : 0) : 0;
      }

      /* action */
      {
        const char *as = yyjson_get_str(action_node);
        size_t al = yyjson_get_len(action_node);
        if (waf_parse_action(as, al, &rule.action) != NGX_OK) {
          if (err) {
            ngx_str_set(&err->message, "非法 action 值");
          }
          return NGX_ERROR;
        }
      }

      /* score/priority */
      {
        yyjson_val *sc = yyjson_obj_get(r, "score");
        yyjson_val *pr = yyjson_obj_get(r, "priority");
        rule.score = (sc && yyjson_is_num(sc)) ? (ngx_int_t)yyjson_get_sint(sc) : 10;
        rule.priority = (pr && yyjson_is_num(pr)) ? (ngx_int_t)yyjson_get_sint(pr) : 0;
      }

      /* tags[] */
      if (waf_copy_tags(pool, yyjson_obj_get(r, "tags"), &rule.tags) != NGX_OK) {
        if (err) {
          ngx_str_set(&err->message, "tags 必须为字符串数组");
        }
        return NGX_ERROR;
      }

      /* phase：显式覆盖或推断，并校验组合 */
      {
        yyjson_val *ph = yyjson_obj_get(r, "phase");
        if (ph && yyjson_is_str(ph)) {
          waf_phase_e phv;
          if (waf_parse_phase_text_ci(yyjson_get_str(ph), yyjson_get_len(ph), &phv) != NGX_OK) {
            if (err) {
              ngx_str_set(&err->message, "phase 取值非法");
            }
            return NGX_ERROR;
          }
          rule.phase = phv;
        } else {
          rule.phase = waf_infer_phase(&rule, log, err);
        }
        if (waf_validate_phase_combo(rule.phase, rule.target, rule.action) != NGX_OK) {
          if (err) {
            ngx_str_set(&err->message, "phase/target/action 组合非法");
          }
          return NGX_ERROR;
        }
      }

      /* 追加到快照数组 */
      waf_compiled_rule_t *slot = ngx_array_push(snap->all_rules);
      if (slot == NULL)
        return NGX_ERROR;
      *slot = rule;

      /* 分桶索引 */
      if (waf_bucket_append(pool, snap, slot->phase, slot->target, slot) != NGX_OK)
        return NGX_ERROR;

      /* 预编译 REGEX/CIDR */
      if (waf_precompile_regexes(pool, log, slot) != NGX_OK)
        return NGX_ERROR;
      if (waf_precompile_cidrs(pool, log, slot) != NGX_OK)
        return NGX_ERROR;
    } else {
      if (err) {
        ngx_str_set(&err->message, "target 必须为字符串或字符串数组");
      }
      return NGX_ERROR;
    }
  }

  /* policies 透传：若存在则克隆为独立只读文档（root=policies 对象） */
  {
    yyjson_val *root = yyjson_doc_get_root(merged_doc);
    yyjson_val *policies = root ? yyjson_obj_get(root, "policies") : NULL;
    if (policies) {
      yyjson_mut_doc *mdoc = yyjson_mut_doc_new(NULL);
      if (mdoc) {
        yyjson_mut_val *p = yyjson_val_mut_copy(mdoc, policies);
        if (p) {
          yyjson_mut_doc_set_root(mdoc, p);
          snap->raw_policies = yyjson_mut_doc_imut_copy(mdoc, NULL);
        }
        yyjson_mut_doc_free(mdoc);
      }
    }
  }

  /* 编译完成后：对所有桶按 priority 稳定排序 */
  for (ngx_uint_t ph = 0; ph < WAF_PHASE_COUNT; ph++) {
    for (ngx_uint_t t = 0; t < 8; t++) {
      if (snap->buckets[ph][t]) {
        waf_sort_bucket_by_priority_stable(snap->buckets[ph][t]);
      }
    }
  }

  *out = snap;
  if (log) {
    ngx_log_error(NGX_LOG_INFO, log, 0, "waf: compiled rules num=%ui", snap->all_rules->nelts);
  }
  /* 清理 uthash 表结构（元素为 pool 分配，将随 pool 一并回收） */
  HASH_CLEAR(hh, id_map);
  return NGX_OK;
}

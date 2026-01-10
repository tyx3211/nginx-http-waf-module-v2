#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/* 本文件不直接使用模块头定义，配置/指令声明移至 ngx_http_waf_config.c */

/* v2 模块骨架：仅保留 ctx、postconfiguration 与外部符号引用 */

/* 外部符号：配置函数与命令表在 ngx_http_waf_config.c 中实现 */
extern void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
extern char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
extern void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
extern char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
extern ngx_command_t ngx_http_waf_commands[];
extern ngx_module_t ngx_http_waf_module; /* 前置声明，供 ngx_http_get_module_*_conf 使用 */

/* 异步请求体读取回调前置声明 */
static void ngx_http_waf_post_read_body_handler(ngx_http_request_t *r);

/* STUB 接口（M2.5）：日志与动作 */
#include "ngx_http_waf_action.h"
#include "ngx_http_waf_compiler.h"
#include "ngx_http_waf_log.h"
#include "ngx_http_waf_stage.h"
#include "ngx_http_waf_utils.h"
#include <ngx_regex.h>

/* 工具函数改为从 utils 复用：ngx_http_waf_collect_request_body 等 */

/* =========================
 *  $waf_* 变量实现与注册
 * ========================= */
static ngx_int_t ngx_http_waf_var_get_blocked(ngx_http_request_t *r,
                                              ngx_http_variable_value_t *v,
                                              uintptr_t data);
static ngx_int_t ngx_http_waf_var_get_action(ngx_http_request_t *r,
                                             ngx_http_variable_value_t *v,
                                             uintptr_t data);
static ngx_int_t ngx_http_waf_var_get_rule_id(ngx_http_request_t *r,
                                              ngx_http_variable_value_t *v,
                                              uintptr_t data);
static ngx_int_t ngx_http_waf_var_get_attack_type(ngx_http_request_t *r,
                                                  ngx_http_variable_value_t *v,
                                                  uintptr_t data);
static ngx_int_t ngx_http_waf_var_get_attack_category(ngx_http_request_t *r,
                                                      ngx_http_variable_value_t *v,
                                                      uintptr_t data);
static ngx_int_t ngx_http_waf_var_get_client_ip(ngx_http_request_t *r,
                                                 ngx_http_variable_value_t *v,
                                                 uintptr_t data);

static ngx_int_t ngx_http_waf_register_variables(ngx_conf_t *cf)
{
  ngx_http_variable_t *var;
  ngx_str_t name;

  name.len = sizeof("waf_blocked") - 1; name.data = (u_char *)"waf_blocked";
  var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
  if (var == NULL) { return NGX_ERROR; }
  var->get_handler = ngx_http_waf_var_get_blocked; var->data = 0;

  name.len = sizeof("waf_action") - 1; name.data = (u_char *)"waf_action";
  var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
  if (var == NULL) { return NGX_ERROR; }
  var->get_handler = ngx_http_waf_var_get_action; var->data = 0;

  name.len = sizeof("waf_rule_id") - 1; name.data = (u_char *)"waf_rule_id";
  var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
  if (var == NULL) { return NGX_ERROR; }
  var->get_handler = ngx_http_waf_var_get_rule_id; var->data = 0;

  name.len = sizeof("waf_attack_type") - 1; name.data = (u_char *)"waf_attack_type";
  var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
  if (var == NULL) { return NGX_ERROR; }
  var->get_handler = ngx_http_waf_var_get_attack_type; var->data = 0;

  name.len = sizeof("waf_attack_category") - 1; name.data = (u_char *)"waf_attack_category";
  var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
  if (var == NULL) { return NGX_ERROR; }
  var->get_handler = ngx_http_waf_var_get_attack_category; var->data = 0;

  /* $waf_client_ip - 真实客户端 IP（尊重 waf_trust_xff 配置） */
  name.len = sizeof("waf_client_ip") - 1; name.data = (u_char *)"waf_client_ip";
  var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
  if (var == NULL) { return NGX_ERROR; }
  var->get_handler = ngx_http_waf_var_get_client_ip; var->data = 0;

  return NGX_OK;
}

static ngx_http_waf_ctx_t *
ngx_http_waf_get_main_ctx(ngx_http_request_t *r)
{
  ngx_http_request_t *mr = r->main ? r->main : r;
  return (ngx_http_waf_ctx_t *)ngx_http_get_module_ctx(mr, ngx_http_waf_module);
}

static ngx_int_t ngx_http_waf_var_get_blocked(ngx_http_request_t *r,
                                              ngx_http_variable_value_t *v,
                                              uintptr_t data)
{
  (void)data;
  ngx_http_waf_ctx_t *ctx = ngx_http_waf_get_main_ctx(r);
  if (ctx && ctx->final_action == WAF_FINAL_BLOCK) {
    v->len = 1; v->data = (u_char *)"1";
  } else {
    v->len = 1; v->data = (u_char *)"0";
  }
  v->valid = 1; v->no_cacheable = 0; v->not_found = 0;
  return NGX_OK;
}

static const char *
ngx_http_waf_action_to_str(waf_final_action_e a)
{
  switch (a) {
    case WAF_FINAL_BLOCK: return "BLOCK";
    case WAF_FINAL_BYPASS: return "BYPASS";
    case WAF_FINAL_NONE: default: return "ALLOW";
  }
}

static ngx_int_t ngx_http_waf_var_get_action(ngx_http_request_t *r,
                                             ngx_http_variable_value_t *v,
                                             uintptr_t data)
{
  (void)data;
  ngx_http_waf_ctx_t *ctx = ngx_http_waf_get_main_ctx(r);
  const char *s = ngx_http_waf_action_to_str(ctx ? ctx->final_action : WAF_FINAL_NONE);
  v->len = (size_t)ngx_strlen(s); v->data = (u_char *)s;
  v->valid = 1; v->no_cacheable = 0; v->not_found = 0;
  return NGX_OK;
}

static const char *
ngx_http_waf_action_type_to_str(waf_final_action_type_e t)
{
  switch (t) {
    case WAF_FINAL_ACTION_TYPE_ALLOW: return "ALLOW";
    case WAF_FINAL_ACTION_TYPE_BYPASS_BY_IP_WHITELIST: return "BYPASS_BY_IP_WHITELIST";
    case WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST: return "BYPASS_BY_URI_WHITELIST";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE: return "BLOCK_BY_RULE";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_REPUTATION: return "BLOCK_BY_REPUTATION";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_IP_BLACKLIST: return "BLOCK_BY_IP_BLACKLIST";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK: return "BLOCK_BY_DYNAMIC_BLOCK";
    default: return "ALLOW";
  }
}

static ngx_int_t ngx_http_waf_var_get_rule_id(ngx_http_request_t *r,
                                              ngx_http_variable_value_t *v,
                                              uintptr_t data)
{
  (void)data;
  ngx_http_waf_ctx_t *ctx = ngx_http_waf_get_main_ctx(r);
  if (ctx && ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE && ctx->block_rule_id > 0) {
    /* 至多 10 位 + 终止符 */
    u_char *p = ngx_pnalloc(r->pool, 16);
    if (p == NULL) { v->len = 0; v->data = (u_char *)""; v->valid = 1; v->no_cacheable = 0; v->not_found = 0; return NGX_OK; }
    u_char *end = ngx_sprintf(p, "%ui", (ngx_uint_t)ctx->block_rule_id);
    v->len = (size_t)(end - p); v->data = p;
  } else {
    v->len = 0; v->data = (u_char *)"";
  }
  v->valid = 1; v->no_cacheable = 0; v->not_found = 0;
  return NGX_OK;
}

static ngx_int_t ngx_http_waf_var_get_attack_type(ngx_http_request_t *r,
                                                  ngx_http_variable_value_t *v,
                                                  uintptr_t data)
{
  (void)data;
  ngx_http_waf_ctx_t *ctx = ngx_http_waf_get_main_ctx(r);
  const char *s = NULL;
  if (ctx && ctx->attack_type) {
    s = ctx->attack_type;
  } else {
    /* 回退到 final_action_type 字符串，保证不为空 */
    s = ngx_http_waf_action_type_to_str(ctx ? ctx->final_action_type : WAF_FINAL_ACTION_TYPE_ALLOW);
  }
  v->len = (size_t)ngx_strlen(s); v->data = (u_char *)s;
  v->valid = 1; v->no_cacheable = 0; v->not_found = 0;
  return NGX_OK;
}

static ngx_int_t ngx_http_waf_var_get_attack_category(ngx_http_request_t *r,
                                                      ngx_http_variable_value_t *v,
                                                      uintptr_t data)
{
  (void)data;
  ngx_http_waf_ctx_t *ctx = ngx_http_waf_get_main_ctx(r);
  const char *s = ngx_http_waf_action_type_to_str(ctx ? ctx->final_action_type : WAF_FINAL_ACTION_TYPE_ALLOW);
  v->len = (size_t)ngx_strlen(s); v->data = (u_char *)s;
  v->valid = 1; v->no_cacheable = 0; v->not_found = 0;
  return NGX_OK;
}

/* $waf_client_ip - 返回真实客户端 IP，尊重 waf_trust_xff 配置 */
static ngx_int_t ngx_http_waf_var_get_client_ip(ngx_http_request_t *r,
                                                 ngx_http_variable_value_t *v,
                                                 uintptr_t data)
{
  (void)data;
  ngx_http_waf_ctx_t *ctx = ngx_http_waf_get_main_ctx(r);
  
  if (ctx && ctx->client_ip != 0) {
    /* 使用 waf_utils_ip_to_str 转换 IP 为字符串 */
    ngx_str_t ip_str = waf_utils_ip_to_str(ctx->client_ip, r->pool);
    if (ip_str.len > 0 && ip_str.data != NULL) {
      v->len = ip_str.len;
      v->data = ip_str.data;
      v->valid = 1;
      v->no_cacheable = 0;
      v->not_found = 0;
      return NGX_OK;
    }
  }
  
  /* 回退到 $remote_addr */
  v->len = r->connection->addr_text.len;
  v->data = r->connection->addr_text.data;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  return NGX_OK;
}

static waf_rc_e waf_stage_ip_allow(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                   ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx)
{
  if (mcf == NULL || lcf == NULL || ctx == NULL || lcf->compiled == NULL) {
    return WAF_RC_CONTINUE;
  }

  /* 获取ip_allow阶段的规则桶（CLIENT_IP是target[0]） */
  ngx_array_t *rules = lcf->compiled->buckets[WAF_PHASE_IP_ALLOW][0];
  if (rules == NULL || rules->nelts == 0) {
    return WAF_RC_CONTINUE;
  }

  /* 使用ctx中已提取的客户端IP（尊重trust_xff配置） */
  in_addr_t client_addr = ctx->client_ip;
  if (client_addr == 0) {
    /* 无效IP（如IPv6或解析失败），跳过检测 */
    return WAF_RC_CONTINUE;
  }

  /* 遍历规则匹配CIDR */
  waf_compiled_rule_t **rule_ptrs = rules->elts;
  for (ngx_uint_t i = 0; i < rules->nelts; i++) {
    waf_compiled_rule_t *rule = rule_ptrs[i];
    if (rule == NULL || rule->compiled_cidrs == NULL) {
      continue;
    }

    ngx_cidr_t *cidrs = rule->compiled_cidrs->elts;
    ngx_uint_t matched = 0;

    for (ngx_uint_t j = 0; j < rule->compiled_cidrs->nelts; j++) {
      if (cidrs[j].family == AF_INET) {
        if ((client_addr & cidrs[j].u.in.mask) == cidrs[j].u.in.addr) {
          matched = 1;
          break;
        }
      }
    }

    /* 应用negate */
    ngx_uint_t matched_pre = matched;
    if (rule->negate) {
      matched = matched ? 0 : 1;
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-debug: ip_allow check rule=%ui matchedPre=%ui negate=%ui matchedFinal=%ui action=%ui",
                  (ngx_uint_t)rule->id, matched_pre, (ngx_uint_t)rule->negate, matched, (ngx_uint_t)rule->action);

    if (!matched) {
      continue;
    }

    /* 命中ip_allow规则：BYPASS */
    if (rule->action == WAF_ACT_BYPASS) {
      waf_event_details_t det = {0};
      det.target_tag = "clientIp";
      det.negate = rule->negate;
      det.rule_tags = rule->tags;
      waf_final_action_type_e hint = WAF_FINAL_ACTION_TYPE_BYPASS_BY_IP_WHITELIST;
      return waf_enforce_bypass(r, mcf, lcf, ctx, rule->id, &det, &hint);
    }
  }

  return WAF_RC_CONTINUE;
}

static waf_rc_e waf_stage_ip_deny(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                  ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx)
{
  if (mcf == NULL || lcf == NULL || ctx == NULL || lcf->compiled == NULL) {
    return WAF_RC_CONTINUE;
  }

  /* 获取ip_block阶段的规则桶（CLIENT_IP是target[0]） */
  ngx_array_t *rules = lcf->compiled->buckets[WAF_PHASE_IP_BLOCK][0];
  if (rules == NULL || rules->nelts == 0) {
    return WAF_RC_CONTINUE;
  }

  /* 使用ctx中已提取的客户端IP（尊重trust_xff配置） */
  in_addr_t client_addr = ctx->client_ip;
  if (client_addr == 0) {
    /* 无效IP（如IPv6或解析失败），跳过检测 */
    return WAF_RC_CONTINUE;
  }

  /* 遍历规则匹配CIDR */
  waf_compiled_rule_t **rule_ptrs = rules->elts;
  for (ngx_uint_t i = 0; i < rules->nelts; i++) {
    waf_compiled_rule_t *rule = rule_ptrs[i];
    if (rule == NULL || rule->compiled_cidrs == NULL) {
      continue;
    }

    ngx_cidr_t *cidrs = rule->compiled_cidrs->elts;
    ngx_uint_t matched = 0;

    for (ngx_uint_t j = 0; j < rule->compiled_cidrs->nelts; j++) {
      if (cidrs[j].family == AF_INET) {
        if ((client_addr & cidrs[j].u.in.mask) == cidrs[j].u.in.addr) {
          matched = 1;
          break;
        }
      }
    }

    /* 应用negate */
    ngx_uint_t matched_pre = matched;
    if (rule->negate) {
      matched = matched ? 0 : 1;
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-debug: ip_deny check rule=%ui matchedPre=%ui negate=%ui matchedFinal=%ui action=%ui",
                  (ngx_uint_t)rule->id, matched_pre, (ngx_uint_t)rule->negate, matched, (ngx_uint_t)rule->action);

    if (!matched) {
      continue;
    }

    /* 命中ip_deny规则：BLOCK */
    if (rule->action == WAF_ACT_DENY) {
      waf_event_details_t det = (waf_event_details_t){0};
      det.target_tag = "clientIp";
      det.negate = rule->negate;
      det.rule_tags = rule->tags;
      /* 通过 hint 明确最终动作类型为 IP 黑名单阻断 */
      waf_final_action_type_e hint = WAF_FINAL_ACTION_TYPE_BLOCK_BY_IP_BLACKLIST;
      waf_rc_e rc = waf_enforce_block_hint(r, mcf, lcf, ctx, NGX_HTTP_FORBIDDEN, rule->id,
                               (ngx_uint_t)(rule->score > 0 ? rule->score : 0), &det, &hint);
      return rc;
    }
  }

  return WAF_RC_CONTINUE;
}

static waf_rc_e waf_stage_reputation_base_add(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                              ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx)
{
  /* 检查动态封禁开关（方案C：LOC级控制） */
  if (lcf && !lcf->dyn_block_enable) {
    return WAF_RC_CONTINUE;
  }

  /* 从编译产物透传的 policies 中解析 baseAccessScore（若不存在则为 0） */
  ngx_uint_t base_score = 0;
  if (lcf && lcf->compiled && lcf->compiled->raw_policies) {
    yyjson_doc *pol = lcf->compiled->raw_policies;
    yyjson_val *root = yyjson_doc_get_root(pol);
    if (root && yyjson_is_obj(root)) {
      yyjson_val *dyn = yyjson_obj_get(root, "dynamicBlock");
      if (dyn && yyjson_is_obj(dyn)) {
        yyjson_val *bs = yyjson_obj_get(dyn, "baseAccessScore");
        if (bs && yyjson_is_num(bs)) {
          base_score = (ngx_uint_t)yyjson_get_sint(bs);
        }
      }
    }
  }

  return waf_enforce_base_add(r, mcf, lcf, ctx, base_score);
}

static waf_rc_e waf_stage_uri_allow(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                    ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx)
{
  if (mcf == NULL || lcf == NULL || ctx == NULL || lcf->compiled == NULL) {
    return WAF_RC_CONTINUE;
  }

  /* 获取uri_allow阶段的规则桶（URI是target[1]） */
  ngx_array_t *rules = lcf->compiled->buckets[WAF_PHASE_URI_ALLOW][1];
  if (rules == NULL || rules->nelts == 0) {
    return WAF_RC_CONTINUE;
  }

  /* 获取请求URI */
  ngx_str_t *uri = &r->uri;

  /* 遍历规则匹配 */
  waf_compiled_rule_t **rule_ptrs = rules->elts;
  for (ngx_uint_t i = 0; i < rules->nelts; i++) {
    waf_compiled_rule_t *rule = rule_ptrs[i];
    if (rule == NULL) {
      continue;
    }

    ngx_uint_t matched = 0;

    /* 根据match类型进行匹配 */
    if (rule->match == WAF_MATCH_CONTAINS) {
      /* CONTAINS模式：子串匹配 */
      if (rule->patterns && rule->patterns->nelts > 0) {
        ngx_str_t *pats = rule->patterns->elts;
        for (ngx_uint_t j = 0; j < rule->patterns->nelts; j++) {
          if (ngx_http_waf_contains_ci(uri, &pats[j], rule->caseless)) {
            matched = 1;
            break;
          }
        }
      }
    } else if (rule->match == WAF_MATCH_EXACT) {
      /* EXACT模式：精确匹配 */
      if (rule->patterns && rule->patterns->nelts > 0) {
        ngx_str_t *pats = rule->patterns->elts;
        for (ngx_uint_t j = 0; j < rule->patterns->nelts; j++) {
          if (ngx_http_waf_equals_ci(uri, &pats[j], rule->caseless)) {
            matched = 1;
            break;
          }
        }
      }
    } else if (rule->match == WAF_MATCH_REGEX) {
      /* REGEX模式：正则匹配 */
      if (rule->compiled_regexes && rule->compiled_regexes->nelts > 0) {
        matched = ngx_http_waf_regex_any_match(rule->compiled_regexes, uri);
      }
    }

    /* 应用negate */
    ngx_uint_t matched_pre = matched;
    if (rule->negate) {
      matched = matched ? 0 : 1;
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-debug: uri_allow check rule=%ui matchedPre=%ui negate=%ui matchedFinal=%ui action=%ui",
                  (ngx_uint_t)rule->id, matched_pre, (ngx_uint_t)rule->negate, matched, (ngx_uint_t)rule->action);

    if (!matched) {
      continue;
    }

    /* 命中uri_allow规则：BYPASS */
    if (rule->action == WAF_ACT_BYPASS) {
      waf_event_details_t det = {0};
      det.target_tag = "uri";
      det.negate = rule->negate;
      det.rule_tags = rule->tags;
      waf_final_action_type_e hint = WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST;
      return waf_enforce_bypass(r, mcf, lcf, ctx, rule->id, &det, &hint);
    }
  }

  return WAF_RC_CONTINUE;
}

static waf_rc_e waf_stage_detect_bundle(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                        ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx)
{
  /* 最小实现：遍历 detect 段 buckets，支持
   * URI/ARGS_COMBINED/ARGS_NAME/ARGS_VALUE/HEADER 的 CONTAINS/REGEX 匹配 */
  if (lcf == NULL || lcf->compiled == NULL) {
    return WAF_RC_CONTINUE;
  }

  waf_compiled_snapshot_t *snap = lcf->compiled;

  /* 工具函数已在文件顶部以 C 形式定义，直接调用 */

  /* decode 缓存：避免对 ARGS_COMBINED 多次解码 */
  ngx_str_t cached_args_combined = ngx_null_string;
  ngx_uint_t cached_args_ready = 0;
  ngx_int_t cached_args_rc = NGX_ERROR;

  /* 遍历 detect 段各 target 的桶 */
  for (ngx_uint_t target = 0; target <= WAF_T_HEADER; target++) {
    ngx_array_t *bucket = snap->buckets[WAF_PHASE_DETECT][target];
    if (bucket == NULL || bucket->nelts == 0)
      continue;

    waf_compiled_rule_t **rules = bucket->elts;
    for (ngx_uint_t i = 0; i < bucket->nelts; i++) {
      waf_compiled_rule_t *rule = rules[i];
      if (rule == NULL)
        continue;

      ngx_uint_t matched = 0;

      switch (rule->target) {
        case WAF_T_URI: {
          ngx_str_t subj = r->uri;
          if (rule->match == WAF_MATCH_CONTAINS) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_contains_ci(&subj, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_EXACT) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_equals_ci(&subj, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_REGEX) {
            matched = ngx_http_waf_regex_any_match(rule->compiled_regexes, &subj);
          }
          break;
        }

        case WAF_T_ARGS_COMBINED: {
          if (!cached_args_ready) {
            cached_args_rc = ngx_http_waf_get_decoded_args_combined(r, &cached_args_combined);
            cached_args_ready = 1;
          }
          if (cached_args_rc != NGX_OK || cached_args_combined.len == 0) {
            matched = 0;
            break;
          }
          ngx_str_t subj = cached_args_combined;
          if (rule->match == WAF_MATCH_CONTAINS) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_contains_ci(&subj, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_EXACT) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_equals_ci(&subj, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_REGEX) {
            matched = ngx_http_waf_regex_any_match(rule->compiled_regexes, &subj);
          }
          break;
        }

        case WAF_T_ARGS_NAME: {
          ngx_str_t subj = r->args;
          if (rule->match == WAF_MATCH_EXACT) {
            matched = ngx_http_waf_args_iter_exact(&subj, /*match_name=*/1, rule->caseless,
                                                   rule->patterns, r->pool);
          } else {
            matched = ngx_http_waf_args_iter_match(&subj, /*match_name=*/1, rule->caseless,
                                                   rule->patterns, rule->compiled_regexes,
                                                   (rule->match == WAF_MATCH_REGEX), r->pool);
          }
          break;
        }

        case WAF_T_ARGS_VALUE: {
          ngx_str_t subj = r->args;
          if (rule->match == WAF_MATCH_EXACT) {
            matched = ngx_http_waf_args_iter_exact(&subj, /*match_name=*/0, rule->caseless,
                                                   rule->patterns, r->pool);
          } else {
            matched = ngx_http_waf_args_iter_match(&subj, /*match_name=*/0, rule->caseless,
                                                   rule->patterns, rule->compiled_regexes,
                                                   (rule->match == WAF_MATCH_REGEX), r->pool);
          }
          break;
        }

        case WAF_T_HEADER: {
          /* 缺失的 HEADER 视为空串以参与匹配（支持 ^$ 白名单 + negate 逻辑） */
          ngx_str_t hv;
          if (!ngx_http_waf_get_header(r, &rule->header_name, &hv)) {
            hv.data = (u_char *)"";
            hv.len = 0;
          }
          if (rule->match == WAF_MATCH_CONTAINS) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_contains_ci(&hv, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_EXACT) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_equals_ci(&hv, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_REGEX) {
            matched = ngx_http_waf_regex_any_match(rule->compiled_regexes, &hv);
            /* 特判：空串与 ^$ */
            if (!matched && hv.len == 0 && rule->patterns && rule->patterns->nelts > 0) {
              ngx_str_t *pats = rule->patterns->elts;
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (pats[k].len == 2 && pats[k].data && pats[k].data[0] == '^' && pats[k].data[1] == '$') {
                  matched = 1;
                  break;
                }
              }
            }
          }
          break;
        }

        case WAF_T_CLIENT_IP: {
          /* CLIENT_IP 匹配由专门阶段处理（IP allow/deny），此处跳过 */
          matched = 0;
          break;
        }

        case WAF_T_BODY: {
          ngx_str_t body;
          if (r->request_body == NULL || r->request_body->bufs == NULL) {
            matched = 0;
            break;
          }
          if (ngx_http_waf_collect_request_body(r, &body) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "waf: collect_request_body failed; treat as empty BODY");
            matched = 0;
            break;
          }
          ngx_str_t body_view = body;
          if (r->headers_in.content_type &&
              r->headers_in.content_type->value.len >=
                  sizeof("application/x-www-form-urlencoded") - 1 &&
              ngx_strncasecmp(r->headers_in.content_type->value.data,
                              (u_char *)"application/x-www-form-urlencoded",
                              sizeof("application/x-www-form-urlencoded") - 1) == 0) {
            ngx_str_t decoded_body;
            if (ngx_http_waf_decode_form_urlencoded(r->pool, &body, &decoded_body) == NGX_OK) {
              body_view = decoded_body;
            }
          }
          if (rule->match == WAF_MATCH_CONTAINS) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_contains_ci(&body_view, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_EXACT) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_equals_ci(&body_view, &pats[k], rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_REGEX) {
            matched = ngx_http_waf_regex_any_match(rule->compiled_regexes, &body_view);
          }
          break;
        }

        default: {
          matched = 0;
          break;
        }
      }

      /* 应用 negate */
      if (rule->negate) {
        matched = matched ? 0 : 1;
      }

      if (!matched) {
        continue;
      }

      /* 命中后执法：DENY/BYPASS/LOG */
      switch (rule->action) {
        case WAF_ACT_DENY: {
          ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                        "waf-debug: enforce DENY rule=%ui target=%ui negate=%ui",
                        (ngx_uint_t)rule->id, (ngx_uint_t)rule->target, (ngx_uint_t)rule->negate);
          waf_event_details_t det = {0};
          det.target_tag = (rule->target == WAF_T_URI)
                                ? "uri"
                                : (rule->target == WAF_T_ARGS_COMBINED)
                                      ? "args"
                                      : (rule->target == WAF_T_ARGS_NAME)
                                            ? "argsName"
                                      : (rule->target == WAF_T_ARGS_VALUE)
                                                  ? "argsValue"
                                                  : (rule->target == WAF_T_HEADER)
                                                        ? (const char *)"header"
                                                        : NULL;
          det.negate = rule->negate;
          det.rule_tags = rule->tags;

          waf_rc_e rc = waf_enforce_block(r, mcf, lcf, ctx, NGX_HTTP_FORBIDDEN, rule->id,
                                          (ngx_uint_t)(rule->score > 0 ? rule->score : 0), &det);
          if (rc == WAF_RC_BLOCK || rc == WAF_RC_BYPASS || rc == WAF_RC_ERROR) {
            return rc;
          }
          /* 继续遍历后续规则 */
          break;
        }
        case WAF_ACT_BYPASS: {
          ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                        "waf-debug: enforce BYPASS rule=%ui target=%ui negate=%ui",
                        (ngx_uint_t)rule->id, (ngx_uint_t)rule->target, (ngx_uint_t)rule->negate);
          waf_event_details_t det2 = {0};
          det2.target_tag = (rule->target == WAF_T_URI)
                                ? "uri"
                                : (rule->target == WAF_T_ARGS_COMBINED)
                                      ? "args"
                                      : (rule->target == WAF_T_ARGS_NAME)
                                            ? "argsName"
                                            : (rule->target == WAF_T_ARGS_VALUE)
                                                  ? "argsValue"
                                                  : (rule->target == WAF_T_HEADER)
                                                        ? (const char *)"header"
                                                        : NULL;
          det2.negate = rule->negate;
          det2.rule_tags = rule->tags;
          waf_final_action_type_e bypass_hint = WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST;

          waf_rc_e rc = waf_enforce_bypass(r, mcf, lcf, ctx, rule->id, &det2, &bypass_hint);
          if (rc == WAF_RC_BLOCK || rc == WAF_RC_BYPASS || rc == WAF_RC_ERROR) {
            return rc;
          }
          /* 继续遍历后续规则 */
          break;
        }
        case WAF_ACT_LOG:
        default: {
          ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                        "waf-debug: enforce LOG rule=%ui target=%ui negate=%ui",
                        (ngx_uint_t)rule->id, (ngx_uint_t)rule->target, (ngx_uint_t)rule->negate);
          waf_event_details_t det3 = {0};
          det3.target_tag = (rule->target == WAF_T_URI)
                                ? "uri"
                                : (rule->target == WAF_T_ARGS_COMBINED)
                                      ? "args"
                                      : (rule->target == WAF_T_ARGS_NAME)
                                            ? "argsName"
                                            : (rule->target == WAF_T_ARGS_VALUE)
                                                  ? "argsValue"
                                                  : (rule->target == WAF_T_HEADER)
                                                        ? (const char *)"header"
                                                        : NULL;
          det3.negate = rule->negate;
          det3.rule_tags = rule->tags;

          waf_enforce_log(r, mcf, lcf, ctx, rule->id,
                          (ngx_uint_t)(rule->score > 0 ? rule->score : 0), &det3);
          /* 继续遍历后续规则 */
          break;
        }
      }
    }
  }

  return WAF_RC_CONTINUE;
}

static ngx_int_t ngx_http_waf_access_handler(ngx_http_request_t *r)
{
  /* 过滤内部请求和子请求（性能优化 + 避免重复检测） */
  WAF_FILTER_INTERNAL_REQUESTS(r);
  WAF_FILTER_SUBREQUESTS(r);

  /* 初始化请求态 ctx */
  ngx_http_waf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
    if (ctx == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    waf_init_ctx(r, ctx); // 初始化ctx（包含日志结构、IP、请求级时间快照）
    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
  }

  /* 获取配置句柄 */
  ngx_http_waf_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
  ngx_http_waf_loc_conf_t *lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

  /* 检查waf on|off开关 */
  if (lcf && !lcf->waf_enable) {
    return NGX_DECLINED;
  }

  /* 五段流水线（前四段与请求体无关，先执行） */
  WAF_STAGE(ctx, waf_stage_ip_allow(r, mcf, lcf, ctx));
  WAF_STAGE(ctx, waf_stage_ip_deny(r, mcf, lcf, ctx));
  WAF_STAGE(ctx, waf_stage_reputation_base_add(r, mcf, lcf, ctx));
  WAF_STAGE(ctx, waf_stage_uri_allow(r, mcf, lcf, ctx));

  /* 是否需要读取请求体？GET/HEAD 或 content-length==0 则跳过读体，BODY 视为空串
   */
  if ((r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) || r->headers_in.content_length_n == 0) {
    WAF_STAGE(ctx, waf_stage_detect_bundle(r, mcf, lcf, ctx));
    waf_action_finalize_allow(r, mcf, lcf, ctx);
    return NGX_DECLINED;
  }

  /* 读取请求体，回调中完成检测与尾部 FINAL */
  ngx_int_t rc = ngx_http_read_client_request_body(
      r, (ngx_http_client_body_handler_pt)ngx_http_waf_post_read_body_handler);
  if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    return rc;
  }
  /* NGX_OK 或 NGX_AGAIN 均返回 NGX_DONE，等待回调推进 */
  return NGX_DONE;
}

static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t *cf)
{
  /* 注册 ACCESS 阶段处理函数（优先级靠前） */
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  if (cmcf == NULL) {
    return NGX_ERROR;
  }

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_waf_access_handler;

  /* 注册 $waf_* 变量 */
  if (ngx_http_waf_register_variables(cf) != NGX_OK) {
    return NGX_ERROR;
  }

  return NGX_OK;
}

static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_waf_postconfiguration, /* postconfiguration */
    ngx_http_waf_create_main_conf,  /* create main conf */
    ngx_http_waf_init_main_conf,    /* init main conf */
    NULL,                           /* create srv conf */
    NULL,                           /* merge srv conf */
    ngx_http_waf_create_loc_conf,   /* create loc conf */
    ngx_http_waf_merge_loc_conf     /* merge loc conf */
};

/* clang-format off */
ngx_module_t ngx_http_waf_module = 
{
  NGX_MODULE_V1,
  &ngx_http_waf_module_ctx, /* module context */
  ngx_http_waf_commands,    /* module directives */
  NGX_HTTP_MODULE,          /* module type */
  NULL,                     /* init master */
  NULL,                     /* init module */
  NULL,                     /* init process */
  NULL,                     /* init thread */
  NULL,                     /* exit thread */
  NULL,                     /* exit process */
  NULL,                     /* exit master */
  NGX_MODULE_V1_PADDING
};
/* clang-format on */

/* 请求体读取完成后的回调：完成检测段与尾部 FINAL；若未早退，则推进到下一个相位
 */
static void ngx_http_waf_post_read_body_handler(ngx_http_request_t *r)
{
  ngx_http_waf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
  ngx_http_waf_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
  ngx_http_waf_loc_conf_t *lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

  if (ctx == NULL) {
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }

  waf_rc_e rc_stage = waf_stage_detect_bundle(r, mcf, lcf, ctx);
  if (rc_stage == WAF_RC_BLOCK) {
    ngx_int_t http_status = ctx->final_status > 0 ? ctx->final_status : NGX_HTTP_FORBIDDEN;
    ngx_http_finalize_request(r, http_status);
    return;
  }
  if (rc_stage == WAF_RC_ERROR) {
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }
  if (rc_stage == WAF_RC_BYPASS) {
    /* BYPASS 已在 action 内完成日志最终落盘；继续后续相位 */
    r->phase_handler++;
    ngx_http_core_run_phases(r);
    return;
  }

  /* 未早退：ALLOW 最终落盘一次并推进 */
  waf_action_finalize_allow(r, mcf, lcf, ctx);
  r->phase_handler++;
  ngx_http_core_run_phases(r);
}

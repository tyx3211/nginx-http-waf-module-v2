#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/* 本文件不直接使用模块头定义，配置/指令声明移至 ngx_http_waf_config.c */

/* v2 模块骨架：仅保留 ctx、postconfiguration 与外部符号引用 */

/* 外部符号：配置函数与命令表在 ngx_http_waf_config.c 中实现 */
extern void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
extern char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf);
extern void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
extern char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                         void *child);
extern ngx_command_t ngx_http_waf_commands[];
extern ngx_module_t
    ngx_http_waf_module; /* 前置声明，供 ngx_http_get_module_*_conf 使用 */

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

static waf_rc_e waf_stage_ip_allow(ngx_http_request_t *r,
                                   ngx_http_waf_main_conf_t *mcf,
                                   ngx_http_waf_loc_conf_t *lcf,
                                   ngx_http_waf_ctx_t *ctx)
{
  (void)mcf;
  (void)lcf;
  (void)ctx;
  ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "waf-stub: ip_allow stage not implemented; continue");
  return WAF_RC_CONTINUE;
}

static waf_rc_e waf_stage_ip_deny(ngx_http_request_t *r,
                                  ngx_http_waf_main_conf_t *mcf,
                                  ngx_http_waf_loc_conf_t *lcf,
                                  ngx_http_waf_ctx_t *ctx)
{
  (void)mcf;
  (void)lcf;
  (void)ctx;
  ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "waf-stub: ip_deny stage not implemented; continue");
  return WAF_RC_CONTINUE;
}

static waf_rc_e waf_stage_reputation_base_add(ngx_http_request_t *r,
                                              ngx_http_waf_main_conf_t *mcf,
                                              ngx_http_waf_loc_conf_t *lcf,
                                              ngx_http_waf_ctx_t *ctx)
{
  ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "waf-stub: reputation base add uses score_delta=0; continue");
  return waf_enforce_base_add(r, mcf, lcf, ctx, 0);
}

static waf_rc_e waf_stage_uri_allow(ngx_http_request_t *r,
                                    ngx_http_waf_main_conf_t *mcf,
                                    ngx_http_waf_loc_conf_t *lcf,
                                    ngx_http_waf_ctx_t *ctx)
{
  (void)mcf;
  (void)lcf;
  (void)ctx;
  ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "waf-stub: uri_allow stage not implemented; continue");
  return WAF_RC_CONTINUE;
}

static waf_rc_e waf_stage_detect_bundle(ngx_http_request_t *r,
                                        ngx_http_waf_main_conf_t *mcf,
                                        ngx_http_waf_loc_conf_t *lcf,
                                        ngx_http_waf_ctx_t *ctx)
{
  /* 最小实现：遍历 detect 段 buckets，支持
   * URI/ARGS_COMBINED/ARGS_NAME/ARGS_VALUE/HEADER 的 CONTAINS/REGEX 匹配 */
  if (lcf == NULL || lcf->compiled == NULL) {
    return WAF_RC_CONTINUE;
  }

  waf_compiled_snapshot_t *snap = lcf->compiled;

  /* 工具函数已在文件顶部以 C 形式定义，直接调用 */

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
            matched =
                ngx_http_waf_regex_any_match(rule->compiled_regexes, &subj);
          }
          break;
        }

        case WAF_T_ARGS_COMBINED: {
          ngx_str_t subj;
          if (ngx_http_waf_get_decoded_args_combined(r, &subj) != NGX_OK ||
              subj.len == 0) {
            matched = 0;
            break;
          }
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
            matched =
                ngx_http_waf_regex_any_match(rule->compiled_regexes, &subj);
          }
          break;
        }

        case WAF_T_ARGS_NAME: {
          ngx_str_t subj = r->args;
          if (rule->match == WAF_MATCH_EXACT) {
            matched = ngx_http_waf_args_iter_exact(&subj, /*match_name=*/1,
                                                   rule->caseless,
                                                   rule->patterns);
          } else {
            matched = ngx_http_waf_args_iter_match(
                &subj, /*match_name=*/1, rule->caseless, rule->patterns,
                rule->compiled_regexes, (rule->match == WAF_MATCH_REGEX));
          }
          break;
        }

        case WAF_T_ARGS_VALUE: {
          ngx_str_t subj = r->args;
          if (rule->match == WAF_MATCH_EXACT) {
            matched = ngx_http_waf_args_iter_exact(&subj, /*match_name=*/0,
                                                   rule->caseless,
                                                   rule->patterns);
          } else {
            matched = ngx_http_waf_args_iter_match(
                &subj, /*match_name=*/0, rule->caseless, rule->patterns,
                rule->compiled_regexes, (rule->match == WAF_MATCH_REGEX));
          }
          break;
        }

        case WAF_T_HEADER: {
          ngx_str_t hv;
          if (ngx_http_waf_get_header(r, &rule->header_name, &hv)) {
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
            } else if (rule->match == WAF_MATCH_REGEX) {
              matched =
                  ngx_http_waf_regex_any_match(rule->compiled_regexes, &hv);
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
            ngx_log_error(
                NGX_LOG_WARN, r->connection->log, 0,
                "waf-stub: collect_request_body failed; treat as empty BODY");
            matched = 0;
            break;
          }
          ngx_str_t body_view = body;
          if (r->headers_in.content_type &&
              r->headers_in.content_type->value.len >=
                  sizeof("application/x-www-form-urlencoded") - 1 &&
              ngx_strncasecmp(r->headers_in.content_type->value.data,
                              (u_char *)"application/x-www-form-urlencoded",
                              sizeof("application/x-www-form-urlencoded") - 1) ==
                  0) {
            ngx_str_t decoded_body;
            if (ngx_http_waf_decode_form_urlencoded(r->pool, &body,
                                                    &decoded_body) == NGX_OK) {
              body_view = decoded_body;
            }
          }
          if (rule->match == WAF_MATCH_CONTAINS) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_contains_ci(&body_view, &pats[k],
                                             rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_EXACT) {
            ngx_str_t *pats = rule->patterns ? rule->patterns->elts : NULL;
            if (pats) {
              for (ngx_uint_t k = 0; k < rule->patterns->nelts; k++) {
                if (ngx_http_waf_equals_ci(&body_view, &pats[k],
                                           rule->caseless)) {
                  matched = 1;
                  break;
                }
              }
            }
          } else if (rule->match == WAF_MATCH_REGEX) {
            matched =
                ngx_http_waf_regex_any_match(rule->compiled_regexes, &body_view);
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
          waf_rc_e rc = waf_enforce_block(
              r, mcf, lcf, ctx, NGX_HTTP_FORBIDDEN, rule->id,
              (ngx_uint_t)(rule->score > 0 ? rule->score : 0));
          if (rc == WAF_RC_BLOCK || rc == WAF_RC_BYPASS || rc == WAF_RC_ERROR) {
            return rc;
          }
          /* 继续遍历后续规则 */
          break;
        }
        case WAF_ACT_BYPASS: {
          waf_rc_e rc = waf_enforce_bypass(r, mcf, lcf, ctx, rule->id);
          if (rc == WAF_RC_BLOCK || rc == WAF_RC_BYPASS || rc == WAF_RC_ERROR) {
            return rc;
          }
          /* 继续遍历后续规则 */
          break;
        }
        case WAF_ACT_LOG:
        default: {
          waf_enforce_log(r, mcf, lcf, ctx, rule->id,
                          (ngx_uint_t)(rule->score > 0 ? rule->score : 0));
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
  /* 初始化请求态 ctx */
  ngx_http_waf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
    if (ctx == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    waf_log_init_ctx(r, ctx);
    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
  }

  /* 获取配置句柄 */
  ngx_http_waf_main_conf_t *mcf =
      ngx_http_get_module_main_conf(r, ngx_http_waf_module);
  ngx_http_waf_loc_conf_t *lcf =
      ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

  /* 五段流水线（前四段与请求体无关，先执行） */
  WAF_STAGE(ctx, waf_stage_ip_allow(r, mcf, lcf, ctx));
  WAF_STAGE(ctx, waf_stage_ip_deny(r, mcf, lcf, ctx));
  WAF_STAGE(ctx, waf_stage_reputation_base_add(r, mcf, lcf, ctx));
  WAF_STAGE(ctx, waf_stage_uri_allow(r, mcf, lcf, ctx));

  /* 是否需要读取请求体？GET/HEAD 或 content-length==0 则跳过读体，BODY 视为空串
   */
  if ((r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)) ||
      r->headers_in.content_length_n == 0) {
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

ngx_module_t ngx_http_waf_module = {
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
    NGX_MODULE_V1_PADDING};

/* 请求体读取完成后的回调：完成检测段与尾部 FINAL；若未早退，则推进到下一个相位
 */
static void ngx_http_waf_post_read_body_handler(ngx_http_request_t *r)
{
  ngx_http_waf_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
  ngx_http_waf_main_conf_t *mcf =
      ngx_http_get_module_main_conf(r, ngx_http_waf_module);
  ngx_http_waf_loc_conf_t *lcf =
      ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

  if (ctx == NULL) {
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }

  waf_rc_e rc_stage = waf_stage_detect_bundle(r, mcf, lcf, ctx);
  if (rc_stage == WAF_RC_BLOCK) {
    ngx_int_t http_status =
        ctx->final_status > 0 ? ctx->final_status : NGX_HTTP_FORBIDDEN;
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

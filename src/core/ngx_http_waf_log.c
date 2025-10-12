#include "ngx_http_waf_log.h"
#include "ngx_http_waf_module_v2.h"
#include "ngx_http_waf_utils.h"
#include <time.h>

/* 外部声明模块（用于获取配置） */
extern ngx_module_t ngx_http_waf_module;

/*
 * ================================================================
 *  完整实现：JSONL 日志系统（M6）
 *  - 使用 yyjson_mut 构建完整 JSON 事件结构
 *  - 输出 JSONL 格式到文件
 *  - 支持 decisive 事件标记与 finalActionType
 * ================================================================
 */

static const char *waf_log_level_str(waf_log_level_e lv)
{
  switch (lv) {
    case WAF_LOG_DEBUG:
      return "DEBUG";
    case WAF_LOG_INFO:
      return "INFO";
    case WAF_LOG_ALERT:
      return "ALERT";
    case WAF_LOG_ERROR:
      return "ERROR";
    default:
      return "NONE";
  }
}

static const char *waf_final_action_type_str(waf_final_action_type_e type)
{
  switch (type) {
    case WAF_FINAL_ACTION_TYPE_ALLOW:
      return "ALLOW";
    case WAF_FINAL_ACTION_TYPE_BYPASS_BY_IP_WHITELIST:
      return "BYPASS_BY_IP_WHITELIST";
    case WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST:
      return "BYPASS_BY_URI_WHITELIST";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE:
      return "BLOCK_BY_RULE";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_REPUTATION:
      return "BLOCK_BY_REPUTATION";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_IP_BLACKLIST:
      return "BLOCK_BY_IP_BLACKLIST";
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK:
      return "BLOCK_BY_DYNAMIC_BLOCK";
    default:
      return "ALLOW";
  }
}

static const char *waf_final_action_str(waf_final_action_e action)
{
  switch (action) {
    case WAF_FINAL_BLOCK:
      return "BLOCK";
    case WAF_FINAL_BYPASS:
      return "BYPASS";
    case WAF_FINAL_NONE:
    default:
      return "ALLOW";
  }
}

void waf_log_init_ctx(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
  if (ctx == NULL || r == NULL)
    return;

  /* 创建 yyjson 文档 */
  ctx->log_doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(ctx->log_doc);
  yyjson_mut_doc_set_root(ctx->log_doc, root);

  /* 创建 events 数组 */
  ctx->events = yyjson_mut_arr(ctx->log_doc);

  ctx->effective_level = WAF_LOG_NONE;
  ctx->total_score = 0;
  ctx->final_status = 0;
  ctx->final_action = WAF_FINAL_NONE;
  ctx->final_action_type = WAF_FINAL_ACTION_TYPE_ALLOW;
  ctx->block_rule_id = 0;
  ctx->has_complete_events = 0;
  ctx->log_flushed = 0;
  ctx->decisive_set = 0;
  /* 移除临时 pending_* 机制，改为调用处聚合参数传递 */

  /* M5增强：获取客户端IP（网络字节序） */
  ngx_http_waf_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
  ngx_flag_t trust_xff = (mcf != NULL) ? mcf->trust_xff : 0;
  ctx->client_ip = waf_utils_get_client_ip(r, trust_xff);

  /* 记录请求级时间快照（毫秒） */
  ctx->request_now_msec = ngx_current_msec;
}

static void waf_log_raise_effective_level(ngx_http_waf_ctx_t *ctx, waf_log_level_e lv)
{
  if (ctx == NULL)
    return;
  if ((int)lv > (int)ctx->effective_level) {
    ctx->effective_level = lv;
  }
}

static ngx_flag_t waf_log_should_collect(ngx_http_waf_main_conf_t *mcf,
                                         ngx_http_waf_ctx_t *ctx,
                                         waf_log_collect_mode_e collect_mode,
                                         waf_log_level_e level)
{
  if (ctx == NULL) return 0;
  if (collect_mode == WAF_LOG_COLLECT_ALWAYS) {
    return 1;
  }
  if (collect_mode == WAF_LOG_COLLECT_LEVEL_GATED) {
    if (mcf == NULL) return 0;
    if (mcf->json_log_level == (ngx_uint_t)WAF_LOG_NONE) return 0;
    return ((ngx_int_t)level >= (ngx_int_t)mcf->json_log_level) ? 1 : 0;
  }
  return 0;
}

void waf_log_append_rule_event(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                               ngx_http_waf_ctx_t *ctx, ngx_uint_t rule_id,
                               const char *intent_str, ngx_uint_t score_delta,
                               const waf_event_details_t *details,
                               waf_log_collect_mode_e collect_mode, waf_log_level_e level)
{
  if (ctx == NULL || ctx->log_doc == NULL || ctx->events == NULL)
    return;
  if (!waf_log_should_collect(mcf, ctx, collect_mode, level))
    return;

  yyjson_mut_doc *doc = ctx->log_doc;
  yyjson_mut_val *event = yyjson_mut_obj(doc);

  yyjson_mut_obj_add_str(doc, event, "type", "rule");
  yyjson_mut_obj_add_uint(doc, event, "ruleId", rule_id);
  if (intent_str) {
    yyjson_mut_obj_add_str(doc, event, "intent", intent_str);
  }
  if (score_delta > 0) {
    yyjson_mut_obj_add_uint(doc, event, "scoreDelta", score_delta);
  }
  yyjson_mut_obj_add_uint(doc, event, "totalScore", ctx->total_score);

  if (details) {
    if (details->matched_pattern.len > 0) {
      yyjson_mut_obj_add_strn(doc, event, "matchedPattern",
                              (const char *)details->matched_pattern.data,
                              details->matched_pattern.len);
      yyjson_mut_obj_add_uint(doc, event, "patternIndex", details->pattern_index);
    }
    if (details->target_tag) {
      yyjson_mut_obj_add_str(doc, event, "target", details->target_tag);
    }
    if (details->negate) {
      yyjson_mut_obj_add_bool(doc, event, "negate", true);
    }
  }

  yyjson_mut_arr_append(ctx->events, event);
  waf_log_raise_effective_level(ctx, level);
}

void waf_log_append_reputation_event(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                     ngx_http_waf_ctx_t *ctx, ngx_uint_t score_delta,
                                     const char *reason, waf_log_collect_mode_e collect_mode,
                                     waf_log_level_e level)
{
  if (ctx == NULL || ctx->log_doc == NULL || ctx->events == NULL)
    return;
  if (!waf_log_should_collect(mcf, ctx, collect_mode, level))
    return;

  yyjson_mut_doc *doc = ctx->log_doc;
  yyjson_mut_val *event = yyjson_mut_obj(doc);

  yyjson_mut_obj_add_str(doc, event, "type", "reputation");
  if (score_delta > 0) {
    yyjson_mut_obj_add_uint(doc, event, "scoreDelta", score_delta);
  }
  yyjson_mut_obj_add_uint(doc, event, "totalScore", ctx->total_score);
  if (reason) {
    yyjson_mut_obj_add_str(doc, event, "reason", reason);
  }

  yyjson_mut_arr_append(ctx->events, event);
  waf_log_raise_effective_level(ctx, level);
}

void waf_log_append_window_reset_event(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                       ngx_http_waf_ctx_t *ctx, ngx_uint_t prev_score,
                                       ngx_msec_t window_start_ms, ngx_msec_t window_end_ms,
                                       waf_log_collect_mode_e collect_mode, waf_log_level_e level)
{
  if (ctx == NULL || ctx->log_doc == NULL || ctx->events == NULL)
    return;

  if (prev_score == 0)
    return; /* 噪声控制：仅在清零前有积分时记录 */

  if (!waf_log_should_collect(mcf, ctx, collect_mode, level))
    return;

  yyjson_mut_doc *doc = ctx->log_doc;
  yyjson_mut_val *event = yyjson_mut_obj(doc);

  yyjson_mut_obj_add_str(doc, event, "type", "reputation_window_reset");
  yyjson_mut_obj_add_uint(doc, event, "prevScore", prev_score);
  yyjson_mut_obj_add_uint(doc, event, "windowStartMs", (ngx_uint_t)window_start_ms);
  yyjson_mut_obj_add_uint(doc, event, "windowEndMs", (ngx_uint_t)window_end_ms);
  yyjson_mut_obj_add_str(doc, event, "reason", "window_expired");
  yyjson_mut_obj_add_str(doc, event, "category", "reputation/dyn_block");

  yyjson_mut_arr_append(ctx->events, event);
  waf_log_raise_effective_level(ctx, level);
}

void waf_log_append_ban_event(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                              ngx_http_waf_ctx_t *ctx, ngx_msec_t window,
                              waf_log_collect_mode_e collect_mode, waf_log_level_e level)
{
  if (ctx == NULL || ctx->log_doc == NULL || ctx->events == NULL)
    return;
  if (!waf_log_should_collect(mcf, ctx, collect_mode, level))
    return;

  yyjson_mut_doc *doc = ctx->log_doc;
  yyjson_mut_val *event = yyjson_mut_obj(doc);

  yyjson_mut_obj_add_str(doc, event, "type", "ban");
  yyjson_mut_obj_add_uint(doc, event, "window", (ngx_uint_t)window);

  yyjson_mut_arr_append(ctx->events, event);
  waf_log_raise_effective_level(ctx, level);
}

void waf_log_append_event_complete(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
                                   waf_log_level_e level)
{
  if (ctx == NULL)
    return;
  waf_log_raise_effective_level(ctx, level);
  ctx->has_complete_events = 1;
}

void waf_log_append_event(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx, waf_log_level_e level)
{
  if (ctx == NULL)
    return;
  waf_log_raise_effective_level(ctx, level);
}

void waf_log_flush(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                   ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx)
{
  if (r == NULL || ctx == NULL)
    return;

  /* 仅输出 error_log 摘要（可选） */
  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "waf-log: final_status=%ui final_action=%ui level=%s "
                "total_score=%ui uri=\"%V\"",
                ctx->final_status, ctx->final_action, waf_log_level_str(ctx->effective_level),
                ctx->total_score, &r->uri);
}

static void waf_log_write_jsonl(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                                 ngx_http_waf_ctx_t *ctx, const char *jsonl)
{
  if (mcf == NULL || jsonl == NULL)
    return;

  /* 检查是否配置了日志路径 */
  if (mcf->json_log_path.len == 0) {
    return; /* 未配置日志文件 */
  }

  /* 打开文件（追加模式） */
  ngx_fd_t fd =
      ngx_open_file(mcf->json_log_path.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, 0644);
  if (fd == NGX_INVALID_FILE) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                  "waf: failed to open json_log file \"%V\"", &mcf->json_log_path);
    return;
  }

  /* 写入 JSONL（一行JSON + 换行符） */
  size_t len = ngx_strlen(jsonl);
  ssize_t n = ngx_write_fd(fd, (void *)jsonl, len);
  if (n != (ssize_t)len) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                  "waf: failed to write json_log, expected %uz bytes, wrote %z", len, n);
  }

  /* 写入换行符 */
  ngx_write_fd(fd, (void *)"\n", 1);

  /* 关闭文件 */
  if (ngx_close_file(fd) == NGX_FILE_ERROR) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                  "waf: failed to close json_log file \"%V\"", &mcf->json_log_path);
  }
}

/* 在最终落盘前集中判定并标记 decisive 事件 */
static void waf_log_mark_decisive_on_flush(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx)
{
  if (ctx == NULL || ctx->events == NULL || ctx->decisive_set)
    return;

  yyjson_mut_doc *doc = ctx->log_doc;
  size_t n = yyjson_mut_arr_size(ctx->events);
  if (n == 0)
    return;

  /* BYPASS：选择最后一条 intent=BYPASS 的规则事件 */
  if (ctx->final_action == WAF_FINAL_BYPASS) {
    for (ngx_int_t i = (ngx_int_t)n - 1; i >= 0; i--) {
      yyjson_mut_val *ev = yyjson_mut_arr_get(ctx->events, (size_t)i);
      yyjson_mut_val *type = yyjson_mut_obj_get(ev, "type");
      yyjson_mut_val *intent = yyjson_mut_obj_get(ev, "intent");
      const char *type_str = type ? yyjson_mut_get_str(type) : NULL;
      const char *intent_str = intent ? yyjson_mut_get_str(intent) : NULL;
      if (type_str && ngx_strcmp(type_str, "rule") == 0 &&
          intent_str && ngx_strcmp(intent_str, "BYPASS") == 0) {
        yyjson_mut_obj_add_bool(doc, ev, "decisive", true);
        ctx->decisive_set = 1;
        return;
      }
    }
    return;
  }

  /* 仅在最终动作为 BLOCK 时选择 decisive */
  if (ctx->final_action != WAF_FINAL_BLOCK) {
    return;
  }

  /* 动态封禁：优先选择最后一条 ban 事件（从后往前） */
  if (ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK) {
    for (ngx_int_t i = (ngx_int_t)n - 1; i >= 0; i--) {
      yyjson_mut_val *ev = yyjson_mut_arr_get(ctx->events, (size_t)i);
      yyjson_mut_val *type = yyjson_mut_obj_get(ev, "type");
      const char *type_str = type ? yyjson_mut_get_str(type) : NULL;
      if (type_str && ngx_strcmp(type_str, "ban") == 0) {
        yyjson_mut_obj_add_bool(doc, ev, "decisive", true);
        ctx->decisive_set = 1;
        return;
      }
    }
    /* 未找到ban事件则继续走规则回退逻辑 */
  }

  /* 规则阻断：按照 blockRuleId 精确匹配，否则回退到最后一条 BLOCK 规则事件 */
  if (ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE && ctx->block_rule_id > 0) {
    for (ngx_int_t i = (ngx_int_t)n - 1; i >= 0; i--) {
      yyjson_mut_val *ev = yyjson_mut_arr_get(ctx->events, (size_t)i);
      yyjson_mut_val *type = yyjson_mut_obj_get(ev, "type");
      yyjson_mut_val *intent = yyjson_mut_obj_get(ev, "intent");
      yyjson_mut_val *rid = yyjson_mut_obj_get(ev, "ruleId");
      const char *type_str = type ? yyjson_mut_get_str(type) : NULL;
      const char *intent_str = intent ? yyjson_mut_get_str(intent) : NULL;
      ngx_uint_t rule_id = rid ? (ngx_uint_t)yyjson_mut_get_uint(rid) : 0;
      if (type_str && ngx_strcmp(type_str, "rule") == 0 &&
          intent_str && ngx_strcmp(intent_str, "BLOCK") == 0 &&
          rule_id == ctx->block_rule_id) {
        yyjson_mut_obj_add_bool(doc, ev, "decisive", true);
        ctx->decisive_set = 1;
        return;
      }
    }
  }

  /* 回退：选择最后一条 intent=BLOCK 的规则事件（从后往前） */
  for (ngx_int_t i = (ngx_int_t)n - 1; i >= 0; i--) {
    yyjson_mut_val *ev = yyjson_mut_arr_get(ctx->events, (size_t)i);
    yyjson_mut_val *type = yyjson_mut_obj_get(ev, "type");
    yyjson_mut_val *intent = yyjson_mut_obj_get(ev, "intent");
    const char *type_str = type ? yyjson_mut_get_str(type) : NULL;
    const char *intent_str = intent ? yyjson_mut_get_str(intent) : NULL;
    if (type_str && ngx_strcmp(type_str, "rule") == 0 &&
        intent_str && ngx_strcmp(intent_str, "BLOCK") == 0) {
      yyjson_mut_obj_add_bool(doc, ev, "decisive", true);
      ctx->decisive_set = 1;
      return;
    }
  }
}

void waf_log_flush_final(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                         ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                         const char *final_action_hint)
{
  if (r == NULL || ctx == NULL)
    return;
  if (ctx->log_flushed)
    return;

  if (ctx->log_doc == NULL) {
    /* 未初始化，仅输出error_log */
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "waf-final: hint=%s final_status=%ui final_action=%ui "
                  "level=%s total_score=%ui uri=\"%V\"",
                  (final_action_hint ? final_action_hint : ""), ctx->final_status,
                  ctx->final_action, waf_log_level_str(ctx->effective_level), ctx->total_score,
                  &r->uri);
    ctx->log_flushed = 1;
    return;
  }

  yyjson_mut_doc *doc = ctx->log_doc;
  yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);

  /* 1. 时间戳（ISO 8601格式） */
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  char time_buf[64];
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  yyjson_mut_obj_add_str(doc, root, "time", time_buf);

  /* 2. 客户端IP（网络序 → 文本） */
  ngx_str_t ip_text = waf_utils_ip_to_str(ctx->client_ip, r->pool);
  if (ip_text.len > 0) {
    yyjson_mut_obj_add_strn(doc, root, "clientIp", (const char *)ip_text.data, ip_text.len);
  }

  /* 3. 请求方法 */
  yyjson_mut_obj_add_strn(doc, root, "method", (const char *)r->method_name.data,
                          r->method_name.len);

  /* 4. URI */
  yyjson_mut_obj_add_strn(doc, root, "uri", (const char *)r->uri.data, r->uri.len);

  /* 5. events 数组 */
  if (ctx->events) {
    yyjson_mut_obj_add_val(doc, root, "events", ctx->events);
  }

  /* 在最终输出前集中判定并标记 decisive 事件 */
  waf_log_mark_decisive_on_flush(r, ctx);

  /* 6. finalAction */
  yyjson_mut_obj_add_str(doc, root, "finalAction", waf_final_action_str(ctx->final_action));

  /* 7. finalActionType */
  yyjson_mut_obj_add_str(doc, root, "finalActionType",
                         waf_final_action_type_str(ctx->final_action_type));

  /* 8. currentGlobalAction（记录当前请求的全局策略） */
  if (lcf != NULL) {
    const char *global_action = (lcf->default_action == WAF_DEFAULT_ACTION_BLOCK) ? "BLOCK" : "LOG";
    yyjson_mut_obj_add_str(doc, root, "currentGlobalAction", global_action);
  }

  /* 9. blockRuleId（仅BLOCK_BY_RULE时） */
  if (ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE && ctx->block_rule_id > 0) {
    yyjson_mut_obj_add_uint(doc, root, "blockRuleId", ctx->block_rule_id);
  }

  /* 10. status */
  if (ctx->final_status > 0) {
    yyjson_mut_obj_add_uint(doc, root, "status", ctx->final_status);
  }

  /* 11. level（顶层日志级别，文本） */
  yyjson_mut_obj_add_str(doc, root, "level", waf_log_level_str(ctx->effective_level));

  /* 输出 JSONL */
  yyjson_write_err werr;
  char *json = yyjson_mut_write_opts(doc, YYJSON_WRITE_NOFLAG, NULL, NULL, &werr);
  if (json) {
    /* 检查日志级别是否需要输出 */
    ngx_flag_t should_log = 0;
    if (ctx->final_action == WAF_FINAL_BLOCK) {
      /* BLOCK 强制输出 */
      should_log = 1;
    } else if (mcf && mcf->json_log_level != (ngx_uint_t)WAF_LOG_NONE) {
      /* 根据配置级别判断 */
      if ((ngx_int_t)ctx->effective_level >= (ngx_int_t)mcf->json_log_level) {
        should_log = 1;
      }
    }

    if (should_log) {
      waf_log_write_jsonl(r, mcf, ctx, json);
    }

    free(json);
  } else {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "waf: failed to serialize JSON: code=%ui",
                  (ngx_uint_t)werr.code);
  }

  /* 输出 error_log 摘要（可选） */
  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "waf-final: hint=%s final_status=%ui final_action=%s "
                "final_action_type=%s level=%s total_score=%ui uri=\"%V\"",
                (final_action_hint ? final_action_hint : ""), ctx->final_status,
                waf_final_action_str(ctx->final_action),
                waf_final_action_type_str(ctx->final_action_type),
                waf_log_level_str(ctx->effective_level), ctx->total_score, &r->uri);

  ctx->log_flushed = 1;
  (void)lcf;
}

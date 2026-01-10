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

static ngx_int_t waf_tag_eq(const char *tag, size_t tag_len, const char *lit)
{
  if (tag == NULL || lit == NULL) {
    return 0;
  }

  size_t lit_len = ngx_strlen(lit);
  if (tag_len != lit_len) {
    return 0;
  }

  return (ngx_strncasecmp((u_char *)tag, (u_char *)lit, tag_len) == 0);
}

static const char *waf_attack_type_from_tag_slice(const char *tag, size_t tag_len)
{
  if (tag == NULL || tag_len == 0) {
    return NULL;
  }

  /* 约定：tags 推荐使用小写；这里做不区分大小写匹配 */
  if (waf_tag_eq(tag, tag_len, "sqli") ||
      waf_tag_eq(tag, tag_len, "sql") ||
      waf_tag_eq(tag, tag_len, "sql-injection") ||
      waf_tag_eq(tag, tag_len, "sql_injection")) {
    return "SQL_INJECTION";
  }
  if (waf_tag_eq(tag, tag_len, "xss")) {
    return "XSS";
  }
  if (waf_tag_eq(tag, tag_len, "cmdi") ||
      waf_tag_eq(tag, tag_len, "command-injection") ||
      waf_tag_eq(tag, tag_len, "command_injection")) {
    return "COMMAND_INJECTION";
  }
  if (waf_tag_eq(tag, tag_len, "xxe")) {
    return "XXE";
  }
  if (waf_tag_eq(tag, tag_len, "ssrf")) {
    return "SSRF";
  }
  if (waf_tag_eq(tag, tag_len, "rce")) {
    return "RCE";
  }
  if (waf_tag_eq(tag, tag_len, "lfi")) {
    return "LFI";
  }
  if (waf_tag_eq(tag, tag_len, "dir_traversal") ||
      waf_tag_eq(tag, tag_len, "directory_traversal") ||
      waf_tag_eq(tag, tag_len, "path_traversal") ||
      waf_tag_eq(tag, tag_len, "path-traversal") ||
      waf_tag_eq(tag, tag_len, "traversal")) {
    return "PATH_TRAVERSAL";
  }
  if (waf_tag_eq(tag, tag_len, "file-upload") ||
      waf_tag_eq(tag, tag_len, "file_upload") ||
      waf_tag_eq(tag, tag_len, "upload")) {
    return "FILE_UPLOAD";
  }
  if (waf_tag_eq(tag, tag_len, "info-leak") ||
      waf_tag_eq(tag, tag_len, "info_leak") ||
      waf_tag_eq(tag, tag_len, "info") ||
      waf_tag_eq(tag, tag_len, "information-disclosure") ||
      waf_tag_eq(tag, tag_len, "information_disclosure")) {
    return "INFO_DISCLOSURE";
  }

  return NULL;
}

static const char *waf_attack_type_from_rule_tags(const ngx_array_t *rule_tags)
{
  if (rule_tags == NULL || rule_tags->nelts == 0) {
    return NULL;
  }

  ngx_str_t *elts = rule_tags->elts;
  for (ngx_uint_t i = 0; i < rule_tags->nelts; i++) {
    if (elts[i].len == 0) {
      continue;
    }
    const char *mapped = waf_attack_type_from_tag_slice((const char *)elts[i].data, (size_t)elts[i].len);
    if (mapped) {
      return mapped;
    }
  }

  return NULL;
}

static const char *waf_attack_type_from_tags_val(yyjson_mut_val *tags)
{
  if (tags == NULL || !yyjson_mut_is_arr(tags)) {
    return NULL;
  }

  size_t n = yyjson_mut_arr_size(tags);
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *it = yyjson_mut_arr_get(tags, i);
    if (it == NULL || !yyjson_mut_is_str(it)) {
      continue;
    }
    const char *tag = yyjson_mut_get_str(it);
    size_t tag_len = yyjson_mut_get_len(it);
    const char *mapped = waf_attack_type_from_tag_slice(tag, tag_len);
    if (mapped) {
      return mapped;
    }
  }

  return NULL;
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
  // if (score_delta > 0) {
    yyjson_mut_obj_add_uint(doc, event, "scoreDelta", score_delta);
  // }
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

    if (details->rule_tags && details->rule_tags->nelts > 0) {
      const char *mapped_attack_type = waf_attack_type_from_rule_tags(details->rule_tags);
      if (mapped_attack_type) {
        yyjson_mut_obj_add_str(doc, event, "attackType", mapped_attack_type);
      }

      yyjson_mut_val *tags_arr = yyjson_mut_arr(doc);
      ngx_str_t *elts = details->rule_tags->elts;
      for (ngx_uint_t i = 0; i < details->rule_tags->nelts; i++) {
        if (elts[i].len == 0) {
          continue;
        }
        yyjson_mut_val *sv = yyjson_mut_strn(doc, (const char *)elts[i].data, elts[i].len);
        if (sv) {
          yyjson_mut_arr_append(tags_arr, sv);
        }
      }
      if (yyjson_mut_arr_size(tags_arr) > 0) {
        yyjson_mut_obj_add_val(doc, event, "tags", tags_arr);
      }
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
  // if (score_delta >= 0) {
    yyjson_mut_obj_add_uint(doc, event, "scoreDelta", score_delta);
  // }
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
  ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "waf: write_jsonl_to_file called, json_log_path.len=%uz", mcf->json_log_path.len);
  if (mcf->json_log_path.len == 0) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "waf: json_log_path not configured, skipping JSONL write");
    return; /* 未配置日志文件 */
  }

  /* 使用 master 打开的 open_files 句柄（worker 复用 fd；USR1 可重开） */
  if (mcf->json_log_of == NULL || mcf->json_log_of->fd == NGX_INVALID_FILE) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "waf: json_log open_file handle invalid for %V", &mcf->json_log_path);
    return;
  }

  size_t len = ngx_strlen(jsonl);
  ssize_t n = ngx_write_fd(mcf->json_log_of->fd, (void *)jsonl, len);
  if (n != (ssize_t)len) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                  "waf: failed to write json_log, expected %uz bytes, wrote %z", len, n);
  }
  ngx_write_fd(mcf->json_log_of->fd, (void *)"\n", 1);
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
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-debug: decisive marking for BYPASS, events=%uz", (size_t)n);
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
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "waf-debug: decisive set at index=%i type=BYPASS", (ngx_int_t)i);
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
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-debug: decisive marking for DYNAMIC_BLOCK, events=%uz", (size_t)n);
    for (ngx_int_t i = (ngx_int_t)n - 1; i >= 0; i--) {
      yyjson_mut_val *ev = yyjson_mut_arr_get(ctx->events, (size_t)i);
      yyjson_mut_val *type = yyjson_mut_obj_get(ev, "type");
      const char *type_str = type ? yyjson_mut_get_str(type) : NULL;
      if (type_str && ngx_strcmp(type_str, "ban") == 0) {
        yyjson_mut_obj_add_bool(doc, ev, "decisive", true);
        ctx->decisive_set = 1;
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "waf-debug: decisive set at index=%i type=ban", (ngx_int_t)i);
        return;
      }
    }
    /* 未找到ban事件则继续走规则回退逻辑 */
  }

  /* 规则阻断：按照 blockRuleId 精确匹配，否则回退到最后一条 BLOCK 规则事件 */
  if (ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE && ctx->block_rule_id > 0) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "waf-debug: decisive marking for BLOCK_BY_RULE ruleId=%ui events=%uz",
                  (ngx_uint_t)ctx->block_rule_id, (size_t)n);
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
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "waf-debug: decisive set at index=%i type=BLOCK ruleId=%ui",
                      (ngx_int_t)i, (ngx_uint_t)rule_id);
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
      ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                    "waf-debug: decisive set at index=%i type=BLOCK(last)", (ngx_int_t)i);
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

  /* 4. Host */
  if (r->headers_in.host && r->headers_in.host->value.len > 0) {
    yyjson_mut_obj_add_strn(doc, root, "host", 
                            (const char *)r->headers_in.host->value.data,
                            r->headers_in.host->value.len);
  }

  /* 4.1 GeoIP Data (Optional) */
  /* Country Code */
  {
      ngx_str_t name = ngx_string("geoip2_data_country_code");
      ngx_uint_t key = ngx_hash_key(name.data, name.len);
      ngx_http_variable_value_t *v = ngx_http_get_variable(r, &name, key);
      if (v && !v->not_found && v->valid && v->len > 0) {
          yyjson_mut_obj_add_strn(doc, root, "country", (const char *)v->data, v->len);
      }
  }
  /* Province */
  {
      ngx_str_t name = ngx_string("geoip2_data_subdivision_name");
      ngx_uint_t key = ngx_hash_key(name.data, name.len);
      ngx_http_variable_value_t *v = ngx_http_get_variable(r, &name, key);
      if (v && !v->not_found && v->valid && v->len > 0) {
          yyjson_mut_obj_add_strn(doc, root, "province", (const char *)v->data, v->len);
      }
  }
  /* City */
  {
      ngx_str_t name = ngx_string("geoip2_data_city_name");
      ngx_uint_t key = ngx_hash_key(name.data, name.len);
      ngx_http_variable_value_t *v = ngx_http_get_variable(r, &name, key);
      if (v && !v->not_found && v->valid && v->len > 0) {
          yyjson_mut_obj_add_strn(doc, root, "city", (const char *)v->data, v->len);
      }
  }

  /* 5. URI */
  yyjson_mut_obj_add_strn(doc, root, "uri", (const char *)r->uri.data, r->uri.len);

  /* 6. events 数组 */
  if (ctx->events) {
    yyjson_mut_obj_add_val(doc, root, "events", ctx->events);
  }

  /* 在最终输出前集中判定并标记 decisive 事件 */
  waf_log_mark_decisive_on_flush(r, ctx);

  /* attackType：用于大屏/审计聚合（优先基于 decisive 规则事件的 tags 推断） */
  const char *attack_type = NULL;
  switch (ctx->final_action_type) {
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_DYNAMIC_BLOCK:
      attack_type = "DYNAMIC_BLOCK";
      break;
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_IP_BLACKLIST:
      attack_type = "IP_BLACKLIST";
      break;
    case WAF_FINAL_ACTION_TYPE_BLOCK_BY_REPUTATION:
      attack_type = "REPUTATION";
      break;
    case WAF_FINAL_ACTION_TYPE_BYPASS_BY_IP_WHITELIST:
      attack_type = "IP_WHITELIST";
      break;
    case WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST:
      attack_type = "URI_WHITELIST";
      break;
    default:
      break;
  }

  if (attack_type == NULL && ctx->events) {
    /* BLOCK_BY_RULE：优先按 blockRuleId 精确匹配对应的规则事件 */
    if (ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE && ctx->block_rule_id > 0) {
      size_t n = yyjson_mut_arr_size(ctx->events);
      for (ngx_int_t i = (ngx_int_t)n - 1; i >= 0; i--) {
        yyjson_mut_val *ev = yyjson_mut_arr_get(ctx->events, (size_t)i);
        if (ev == NULL) {
          continue;
        }

        yyjson_mut_val *type = yyjson_mut_obj_get(ev, "type");
        const char *type_str = type ? yyjson_mut_get_str(type) : NULL;
        if (type_str == NULL || ngx_strcmp(type_str, "rule") != 0) {
          continue;
        }

        yyjson_mut_val *rid = yyjson_mut_obj_get(ev, "ruleId");
        if (rid && yyjson_mut_is_uint(rid) && (ngx_uint_t)yyjson_mut_get_uint(rid) == ctx->block_rule_id) {
          yyjson_mut_val *atype = yyjson_mut_obj_get(ev, "attackType");
          if (atype && yyjson_mut_is_str(atype)) {
            attack_type = yyjson_mut_get_str(atype);
          }
          if (attack_type == NULL) {
            yyjson_mut_val *tags = yyjson_mut_obj_get(ev, "tags");
            attack_type = waf_attack_type_from_tags_val(tags);
          }
          break;
        }
      }
    }

    /* 回退：使用 decisive 规则事件的 tags 推断 */
    size_t n = yyjson_mut_arr_size(ctx->events);
    for (ngx_int_t i = (ngx_int_t)n - 1; i >= 0; i--) {
      yyjson_mut_val *ev = yyjson_mut_arr_get(ctx->events, (size_t)i);
      if (ev == NULL) {
        continue;
      }
      yyjson_mut_val *dec = yyjson_mut_obj_get(ev, "decisive");
      if (dec == NULL || !yyjson_mut_is_true(dec)) {
        continue;
      }

      yyjson_mut_val *type = yyjson_mut_obj_get(ev, "type");
      const char *type_str = type ? yyjson_mut_get_str(type) : NULL;
      if (type_str && ngx_strcmp(type_str, "rule") == 0) {
        yyjson_mut_val *atype = yyjson_mut_obj_get(ev, "attackType");
        if (atype && yyjson_mut_is_str(atype)) {
          attack_type = yyjson_mut_get_str(atype);
        }
        if (attack_type == NULL) {
          yyjson_mut_val *tags = yyjson_mut_obj_get(ev, "tags");
          attack_type = waf_attack_type_from_tags_val(tags);
        }
      }
      break;
    }
  }

  if (attack_type == NULL &&
      ctx->final_action == WAF_FINAL_BLOCK &&
      ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE) {
    attack_type = "OTHER";
  }

  if (attack_type) {
    yyjson_mut_obj_add_str(doc, root, "attackType", attack_type);
  }
  /* 保存到 ctx，供 $waf_attack_type 与 access_log 使用 */
  ctx->attack_type = attack_type;

  /* 7. finalAction */
  yyjson_mut_obj_add_str(doc, root, "finalAction", waf_final_action_str(ctx->final_action));

  /* 8. finalActionType */
  yyjson_mut_obj_add_str(doc, root, "finalActionType",
                         waf_final_action_type_str(ctx->final_action_type));

  /* 9. currentGlobalAction（记录当前请求的全局策略） */
  if (lcf != NULL) {
    const char *global_action = (lcf->default_action == WAF_DEFAULT_ACTION_BLOCK) ? "BLOCK" : "LOG";
    yyjson_mut_obj_add_str(doc, root, "currentGlobalAction", global_action);
  }

  /* 10. blockRuleId（仅BLOCK_BY_RULE时） */
  if (ctx->final_action_type == WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE && ctx->block_rule_id > 0) {
    yyjson_mut_obj_add_uint(doc, root, "blockRuleId", ctx->block_rule_id);
  }

  /* 11. status */
  if (ctx->final_status > 0) {
    yyjson_mut_obj_add_uint(doc, root, "status", ctx->final_status);
  }

  /* 12. level（顶层日志级别，文本） */
  yyjson_mut_obj_add_str(doc, root, "level", waf_log_level_str(ctx->effective_level));

  /* 输出 JSONL */
  yyjson_write_err werr;
  char *json = yyjson_mut_write_opts(doc, YYJSON_WRITE_NOFLAG, NULL, NULL, &werr);
  if (json) {
    /* 检查日志级别是否需要输出 */
    ngx_flag_t should_log = 0;
    if (ctx->final_action == WAF_FINAL_BLOCK || ctx->final_action == WAF_FINAL_BYPASS) {
      /* BLOCK/BYPASS 强制输出（decisive events） */
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

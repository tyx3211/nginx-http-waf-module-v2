#ifndef NGX_HTTP_WAF_LOG_H
#define NGX_HTTP_WAF_LOG_H

#include "ngx_http_waf_module_v2.h"
#include "ngx_http_waf_types.h"
#include <ngx_core.h>
#include <ngx_http.h>
#include <yyjson/yyjson.h>

/*
 * ================================================================
 *  完整实现：JSONL 日志系统（M6）
 *  - 记录完整事件结构（rule/reputation/ban/bypass）
 *  - 输出 JSONL 格式日志到文件
 *  - 支持 decisive 事件标记与 finalActionType
 * ================================================================
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  WAF_LOG_NONE = 0,
  WAF_LOG_DEBUG = 1,
  WAF_LOG_INFO = 2,
  WAF_LOG_ALERT = 3,
  WAF_LOG_ERROR = 4
} waf_log_level_e;

/* 最终动作类型（用于JSONL输出） */
typedef enum {
  WAF_FINAL_ACTION_TYPE_ALLOW = 0,
  WAF_FINAL_ACTION_TYPE_BYPASS_BY_IP_WHITELIST,
  WAF_FINAL_ACTION_TYPE_BYPASS_BY_URI_WHITELIST,
  WAF_FINAL_ACTION_TYPE_BLOCK_BY_RULE,
  WAF_FINAL_ACTION_TYPE_BLOCK_BY_REPUTATION,
  WAF_FINAL_ACTION_TYPE_BLOCK_BY_IP_BLACKLIST
} waf_final_action_type_e;

typedef struct ngx_http_waf_ctx_s {
  yyjson_mut_doc *log_doc;          /* JSONL文档（请求创建，flush时写入） */
  yyjson_mut_val *events;           /* events数组 */
  waf_log_level_e effective_level;  /* 本次请求的整体日志级别 */
  ngx_uint_t total_score;           /* 动态信誉累计分 */
  ngx_uint_t final_status;          /* 最终 HTTP 状态（若有） */
  waf_final_action_e final_action;  /* 最终动作：NONE/BLOCK/BYPASS */
  waf_final_action_type_e final_action_type; /* 最终动作类型（用于JSONL） */
  ngx_uint_t block_rule_id;         /* 导致阻断的规则ID（仅BLOCK_BY_RULE时有效） */
  unsigned has_complete_events : 1; /* 是否写入过完整性事件 */
  unsigned log_flushed : 1;         /* 是否已最终落盘（去重保护） */
  unsigned decisive_set : 1;        /* 是否已设置decisive事件（同一请求最多一个） */
  /* 客户端IP（用于动态封禁、日志记录，主机字节序uint32_t） */
  ngx_uint_t client_ip;
} ngx_http_waf_ctx_t;

void waf_log_init_ctx(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx);

/* 记录规则事件 */
void waf_log_append_rule_event(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
                               ngx_uint_t rule_id, const char *target_tag, const char *intent_str,
                               ngx_uint_t score_delta, const ngx_str_t *matched_pattern,
                               ngx_uint_t pattern_index, ngx_flag_t negate, ngx_flag_t decisive);

/* 记录reputation事件 */
void waf_log_append_reputation_event(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
                                     ngx_uint_t score_delta, const char *reason);

/* 记录ban事件 */
void waf_log_append_ban_event(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx, ngx_msec_t window);

/* 完整性接口：一定附加事件并提升 effective_level */
void waf_log_append_event_complete(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx,
                                   waf_log_level_e level);

/* 常规接口：级别不足可跳过 */
void waf_log_append_event(ngx_http_request_t *r, ngx_http_waf_ctx_t *ctx, waf_log_level_e level);

/* 最终落盘（存根阶段仅 error_log 一行摘要；BLOCK/BYPASS 强制输出） */
void waf_log_flush(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                   ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx);

/* 统一最终落盘接口（建议被 action 在 BLOCK/BYPASS 以及 handler 尾部调用） */
void waf_log_flush_final(ngx_http_request_t *r, ngx_http_waf_main_conf_t *mcf,
                         ngx_http_waf_loc_conf_t *lcf, ngx_http_waf_ctx_t *ctx,
                         const char *final_action_hint /* "BLOCK"|"BYPASS"|"ALLOW"|NULL */);

#ifdef __cplusplus
}
#endif

#endif /* NGX_HTTP_WAF_LOG_H */

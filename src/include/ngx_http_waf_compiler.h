#ifndef NGX_HTTP_WAF_COMPILER_H
#define NGX_HTTP_WAF_COMPILER_H

#include "ngx_http_waf_module_v2.h"

/*
 * 编译期快照（M2）：
 * - 输入：M1 生成的最终只读 yyjson_doc（字段已基本校验，targets 已归一）
 * - 输出：只读编译快照结构（便于运行期零分配执行）
 * - 目标：提供最小可用集，后续在 M2 阶段逐步增强（REGEX/CIDR
 * 预编译、分桶、排序等）
 */

/* 规则匹配类型 */
typedef enum {
  WAF_MATCH_CONTAINS = 0,
  WAF_MATCH_EXACT,
  WAF_MATCH_REGEX,
  WAF_MATCH_CIDR
} waf_match_e;

/* 规则目标 */
typedef enum {
  WAF_T_CLIENT_IP = 0,
  WAF_T_URI,
  WAF_T_ARGS_COMBINED,
  WAF_T_ARGS_NAME,
  WAF_T_ARGS_VALUE,
  WAF_T_BODY,
  WAF_T_HEADER
} waf_target_e;

/* 动作 */
typedef enum { WAF_ACT_DENY = 0,
               WAF_ACT_LOG,
               WAF_ACT_BYPASS } waf_action_e;

/* 执行段（phase） */
typedef enum {
  WAF_PHASE_IP_ALLOW = 0,
  WAF_PHASE_IP_BLOCK,
  WAF_PHASE_URI_ALLOW,
  WAF_PHASE_DETECT,
  WAF_PHASE_COUNT
} waf_phase_e;

/* 单条编译后规则（最小集） */
typedef struct {
  ngx_uint_t id;         /* 规则 ID */
  waf_target_e target;   /* 目标 */
  ngx_str_t header_name; /* 当 target=HEADER 时有效 */
  waf_match_e match;     /* 匹配类型 */
  ngx_array_t *patterns; /* ngx_array_t(ngx_str_t)，OR 语义 */
  ngx_flag_t caseless;   /* 是否大小写不敏感 */
  ngx_flag_t negate;     /* 是否取反（命中即不命中，未命中即命中） */
  waf_action_e action;   /* 动作 */
  waf_phase_e phase;     /* 执行段（由显式 phase 或 target+action 推断） */
  ngx_int_t score;       /* 评分（BYPASS 可忽略），默认 10 */
  ngx_int_t priority;    /* 检测段内部排序用，默认 0 */
  ngx_array_t *tags;     /* ngx_array_t(ngx_str_t) */
  /* 预编译产物 */
  ngx_array_t *compiled_regexes; /* ngx_array_t(ngx_regex_t*)，仅 REGEX */
  ngx_array_t *compiled_cidrs;   /* ngx_array_t(ngx_cidr_t)，仅 CIDR */
} waf_compiled_rule_t;

/* 编译期快照：包含全部规则与按 phase/target 的分桶索引 */
typedef struct waf_compiled_snapshot_s {
  ngx_pool_t *pool;       /* 归属内存池（通常为配置期 pool） */
  ngx_array_t *all_rules; /* ngx_array_t(waf_compiled_rule_t) */
  /* 透传策略：policies 等（M2 最小集仅原样保存） */
  yyjson_doc *raw_policies; /* 可选：从入口 JSON 透传 */

  /* 分桶：简单起见，每个桶保存指向 all_rules 元素的指针数组 */
  ngx_array_t *buckets[WAF_PHASE_COUNT][8]; /* 8=目标种类上限（与 waf_target_e 对齐） */
} waf_compiled_snapshot_t;

/*
 * 编译入口：将 M1 产出的 yyjson_doc 编译为快照
 * 返回：成功 NGX_OK；失败 NGX_ERROR（err 若非空则填充）
 */
ngx_int_t ngx_http_waf_compile_rules(ngx_pool_t *pool, ngx_log_t *log, yyjson_doc *merged_doc,
                                     waf_compiled_snapshot_t **out, ngx_http_waf_json_error_t *err);

#endif /* NGX_HTTP_WAF_COMPILER_H */

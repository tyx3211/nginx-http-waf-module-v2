#ifndef NGX_HTTP_WAF_MODULE_V2_H
#define NGX_HTTP_WAF_MODULE_V2_H

#include <ngx_core.h>
#include <ngx_http.h>

/*
 * v2 公共头文件入口
 * - 仅放置对外可见的最小类型/结构/函数声明
 * - 详细实现分别在 json/utils/module 等子单元
 */

/* M5运维指令：waf_default_action枚举 */
typedef enum {
  WAF_DEFAULT_ACTION_BLOCK = 0, /* 默认：拦截 */
  WAF_DEFAULT_ACTION_LOG = 1,   /* 仅记录 */
} waf_default_action_e;

/* JSON 解析错误类型（MVP） */
typedef struct {
  ngx_str_t file;         /* 源文件路径（若有） */
  ngx_str_t json_pointer; /* JSON pointer，指向具体错误位置 */
  ngx_str_t message;      /* 错误中文描述 */
} ngx_http_waf_json_error_t;

/* JSON 解析 API（骨架） */
struct yyjson_doc;
struct yyjson_mut_doc;

typedef struct yyjson_doc yyjson_doc;
typedef struct yyjson_mut_doc yyjson_mut_doc;

/* 扩展合并的默认最大递归深度（包含根），防止配置炸弹 */
#ifndef WAF_JSON_MAX_EXTENDS_DEPTH
#define WAF_JSON_MAX_EXTENDS_DEPTH 5
#endif

/*
 * 从路径加载并解析 JSON 工件（含 extends 合并）。
 * - 成功返回只读 yyjson_doc*（模块生命周期内有效）
 * - 失败返回 NULL，并在 err 填充错误信息
 */
/*
 * max_depth 语义：
 * - 0 表示不限制深度（仍执行环检测）
 * - >0 表示包含根在内的最大递归层级
 */
yyjson_doc *ngx_http_waf_json_load_and_merge(ngx_pool_t *pool, ngx_log_t *log,
                                             const ngx_str_t *base_dir, const ngx_str_t *entry_path,
                                             ngx_uint_t max_depth, ngx_http_waf_json_error_t *err);

/* 常用工具（骨架） */
/* 将相对路径按 base_dir 解析为绝对路径；结果分配在 pool */
ngx_int_t ngx_http_waf_join_path(ngx_pool_t *pool, const ngx_str_t *base_dir, const ngx_str_t *path,
                                 ngx_str_t *out_abs);

/* 提取路径的目录部分（不包含末尾文件名），结果分配在 pool */
ngx_int_t ngx_http_waf_dirname(ngx_pool_t *pool, const ngx_str_t *path, ngx_str_t *out_dir);

/* v2 main conf（Nginx 指令承载处） */
typedef struct {
  /* 0 表示不限；>0 表示包含根在内的最大 extends 深度 */
  ngx_uint_t json_extends_max_depth;
  /* JSON 根目录（仅 http/main 级设置），供相对路径解析 */
  ngx_str_t jsons_dir;
  /* JSONL 日志（M2.5 存根：仅配置存储；M6 落地写盘） */
  ngx_str_t json_log_path;   /* off | 路径 */
  ngx_uint_t json_log_level; /* debug|info|alert|error|off */
  /* 由 master 在启动/USR1 时统一打开，worker 复用 fd（通过 cycle->open_files） */
  ngx_open_file_t *json_log_of;
  /* 动态信誉共享内存（M2.5：创建 zone；M5：执法） */
  ngx_str_t shm_zone_raw;   /* 兼容保留：若通过字符串配置 */
  ngx_shm_zone_t *shm_zone; /* 共享内存区句柄（M2.5 初始化） */
  ngx_str_t shm_zone_name;  /* 区域名称 */
  size_t shm_zone_size;     /* 区域大小（字节） */
  /* 动态封禁参数（M5） */
  ngx_uint_t dyn_block_threshold; /* 评分阈值（默认100，0表示禁用；封禁条件：score > threshold） */
  ngx_msec_t dyn_block_window;    /* 评分窗口（毫秒，默认60000=1分钟） */
  ngx_msec_t dyn_block_duration;  /* 封禁时长（毫秒，默认1800000=30分钟） */
  /* M5全局运维指令（MAIN级，不继承） */
  ngx_flag_t trust_xff;                /* waf_trust_xff on|off（默认off） */
} ngx_http_waf_main_conf_t;

/* v2 loc conf（可在 http/server/location 级配置与继承） */
typedef struct {
  /* 0 表示不限；>0 表示包含根在内的最大 extends 深度；未设置时为
   * NGX_CONF_UNSET_UINT */
  ngx_uint_t json_extends_max_depth;

  /* 规则入口文件路径（相对路径由解析器在合并时解析）；未设置时 len=0 */
  ngx_str_t rules_json_path;

  /* 合并后（post-merge）解析得到的只读文档句柄（M1 完成后填充）；允许为空 */
  yyjson_doc *rules_doc;

  /* 编译期只读快照（M2 完成后填充）；允许为空 */
  struct waf_compiled_snapshot_s *compiled;

  /* M5运维指令（HTTP/SRV/LOC，可继承） */
  ngx_flag_t waf_enable;       /* waf on|off（默认on） */
  ngx_flag_t dyn_block_enable; /* waf_dynamic_block_enable on|off（默认off，方案C） */
  waf_default_action_e default_action; /* waf_default_action BLOCK|LOG（默认BLOCK） */
} ngx_http_waf_loc_conf_t;

#endif /* NGX_HTTP_WAF_MODULE_V2_H */

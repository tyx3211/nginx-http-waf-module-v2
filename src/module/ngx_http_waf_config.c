#include "ngx_http_waf_compiler.h"
#include "ngx_http_waf_dynamic_block.h"
#include "ngx_http_waf_log.h"
#include "ngx_http_waf_module_v2.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdlib.h>
#include <yyjson/yyjson.h>

/*
 * 指令与配置：create/merge 与命令表
 * 说明：将配置相关逻辑与模块骨架分离，保持层级清晰。
 */

extern ngx_module_t ngx_http_waf_module; /* 用于 merge 时获取 main_conf */

/* 前置声明：自定义指令处理函数（M2.5 共享内存创建） */
static char *ngx_http_waf_set_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* 自定义 setter：解析 waf_json_log_level debug|info|alert|error|off */
static char *ngx_http_waf_set_json_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* 自定义 setter：解析 waf_json_log 路径并展开为绝对路径 */
static char *ngx_http_waf_set_json_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* 自定义 setter：解析 waf_default_action block|log，允许同级后者覆盖前者 */
static char *ngx_http_waf_set_default_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* 主配置 */
void *ngx_http_waf_create_main_conf(ngx_conf_t *cf)
{
  ngx_http_waf_main_conf_t *mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));
  if (mcf == NULL) {
    return NULL;
  }
  mcf->json_extends_max_depth = WAF_JSON_MAX_EXTENDS_DEPTH; /* 默认 5；0 表示不限 */
  mcf->jsons_dir.len = 0;
  mcf->jsons_dir.data = NULL;
  mcf->json_log_path.len = 0;
  mcf->json_log_path.data = NULL;
  mcf->json_log_level = NGX_CONF_UNSET_UINT; /* 改为未设置哨兵 */
  mcf->shm_zone_raw.len = 0;
  mcf->shm_zone_raw.data = NULL;
  mcf->shm_zone = NULL;
  mcf->shm_zone_name.len = 0;
  mcf->shm_zone_name.data = NULL;
  mcf->shm_zone_size = 0;
  mcf->json_log_of = NULL;
  /* 动态封禁默认值（M5） */
  mcf->dyn_block_threshold = NGX_CONF_UNSET_UINT;   /* 改为未设置哨兵 */
  mcf->dyn_block_window = NGX_CONF_UNSET_MSEC;      /* 改为未设置哨兵 */
  mcf->dyn_block_duration = NGX_CONF_UNSET_MSEC;    /* 改为未设置哨兵 */
  /* M5全局运维指令（MAIN级） */
  mcf->trust_xff = NGX_CONF_UNSET;                  /* 改为未设置哨兵 */
  return mcf;
}

char *ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf)
{
  ngx_http_waf_main_conf_t *mcf = conf;
  (void)cf;

  /* 回填默认值 */
  if (mcf->json_log_level == NGX_CONF_UNSET_UINT) {
    mcf->json_log_level = (ngx_uint_t)WAF_LOG_OFF; /* 默认 off */
  }
  if (mcf->dyn_block_threshold == NGX_CONF_UNSET_UINT) {
    mcf->dyn_block_threshold = 1000;
  }
  if (mcf->dyn_block_window == NGX_CONF_UNSET_MSEC) {
    mcf->dyn_block_window = 60000;
  }
  if (mcf->dyn_block_duration == NGX_CONF_UNSET_MSEC) {
    /* 默认改为 30 分钟（1800000ms） */
    mcf->dyn_block_duration = 1800000;
  }
  if (mcf->trust_xff == NGX_CONF_UNSET) {
    mcf->trust_xff = 0; /* off */
  }

  /* 允许 json_extends_max_depth=0（不限）；>0 原样保留 */
  return NGX_CONF_OK;
}

/* loc 配置 */
void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_waf_loc_conf_t *lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
  if (lcf == NULL) {
    return NULL;
  }
  lcf->json_extends_max_depth = NGX_CONF_UNSET_UINT;
  lcf->rules_json_path.len = 0;
  lcf->rules_json_path.data = NULL;
  lcf->rules_doc = NULL;
  /* M5运维指令默认值（仅LOC级可继承的） */
  lcf->waf_enable = NGX_CONF_UNSET;
  lcf->dyn_block_enable = NGX_CONF_UNSET; /* 方案C：动态封禁开关（LOC级） */
  lcf->default_action = (waf_default_action_e)NGX_CONF_UNSET; /* waf_default_action（LOC级） */
  return lcf;
}

char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_waf_loc_conf_t *prev = parent;
  ngx_http_waf_loc_conf_t *conf = child;

  ngx_http_waf_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

  ngx_log_error(NGX_LOG_INFO, cf->log, 0, "waf: merge_loc_conf called, conf->rules_json_path.len=%uz prev->rules_json_path.len=%uz",
                conf->rules_json_path.len, prev->rules_json_path.len);

  ngx_conf_merge_uint_value(conf->json_extends_max_depth, prev->json_extends_max_depth,
                            mcf ? mcf->json_extends_max_depth : WAF_JSON_MAX_EXTENDS_DEPTH);

  if (conf->rules_json_path.len == 0 && prev->rules_json_path.len != 0) {
    conf->rules_json_path = prev->rules_json_path;
  }

  /* M5运维指令合并（仅LOC级可继承的） */
  ngx_conf_merge_value(conf->waf_enable, prev->waf_enable, 1);             /* 默认启用 */
  ngx_conf_merge_value(conf->dyn_block_enable, prev->dyn_block_enable, 0); /* 默认关闭（方案C） */
  if (conf->default_action == (waf_default_action_e)NGX_CONF_UNSET) {
    conf->default_action = (prev->default_action != (waf_default_action_e)NGX_CONF_UNSET)
                               ? prev->default_action
                               : WAF_DEFAULT_ACTION_BLOCK;
  }

  /* 合并完成后按最终 max_depth 尝试解析规则（存根：仅调用接口并记录错误） */
  if (conf->rules_json_path.len != 0) {
    ngx_http_waf_json_error_t err;
    err.file.len = 0;
    err.file.data = NULL;
    err.json_pointer.len = 0;
    err.json_pointer.data = NULL;
    err.message.len = 0;
    err.message.data = NULL;

    conf->rules_doc = ngx_http_waf_json_load_and_merge(
        cf->pool, cf->log, (mcf && mcf->jsons_dir.len != 0) ? &mcf->jsons_dir : NULL,
        &conf->rules_json_path, conf->json_extends_max_depth, &err);
    if (conf->rules_doc == NULL) {
      ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                    "waf: failed to load rules_json %V: file=%V ptr=%V msg=%V",
                    &conf->rules_json_path, &err.file, &err.json_pointer, &err.message);
      return NGX_CONF_ERROR;
    } else {
      yyjson_val *root = yyjson_doc_get_root(conf->rules_doc);
      yyjson_val *rules = root ? yyjson_obj_get(root, "rules") : NULL;
      size_t cnt = (rules && yyjson_is_arr(rules)) ? yyjson_arr_size(rules) : 0;
      ngx_log_error(NGX_LOG_INFO, cf->log, 0, "waf: merged rules %uz from %V (depth=%ui)",
                    (ngx_uint_t)cnt, &conf->rules_json_path, conf->json_extends_max_depth);

#if defined(WAF_DEBUG_FINAL_DOC)
      /* 输出 final_doc（单行 JSON，调试专用；生产默认关闭） */
      size_t out_len = 0;
      yyjson_write_err werr;
      char *json = yyjson_write_opts(conf->rules_doc, /*flags=*/0, /*alc=*/NULL, &out_len, &werr);
      if (json) {
        ngx_log_error(NGX_LOG_INFO, cf->log, 0, "waf: final_doc: %s", json);
        free(json);
      } else {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0, "waf: final_doc dump failed: code=%ui",
                      (ngx_uint_t)werr.code);
      }
#endif

      /* M2：调用编译器生成只读快照并挂载到 lcf */
      {
        waf_compiled_snapshot_t *snap = NULL;
        ngx_http_waf_json_error_t c_err;
        c_err.file.len = 0;
        c_err.file.data = NULL;
        c_err.json_pointer.len = 0;
        c_err.json_pointer.data = NULL;
        c_err.message.len = 0;
        c_err.message.data = NULL;
        if (ngx_http_waf_compile_rules(cf->pool, cf->log, conf->rules_doc, &snap, &c_err) !=
            NGX_OK) {
          ngx_log_error(NGX_LOG_ERR, cf->log, 0, "waf: compile failed: file=%V ptr=%V msg=%V",
                        &c_err.file, &c_err.json_pointer, &c_err.message);
          return NGX_CONF_ERROR;
        }
        conf->compiled = snap;
      }
    }
  }

  return NGX_CONF_OK;
}

/* 指令表（http/srv/loc 级） */
/* clang-format off */
ngx_command_t ngx_http_waf_commands[] = {
    {
      ngx_string("waf_json_extends_max_depth"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, json_extends_max_depth),
      NULL
    },
    {
      ngx_string("waf_jsons_dir"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, jsons_dir),
      NULL
    },
    {
      ngx_string("waf_rules_json"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, rules_json_path),
      NULL
    },
    {
      ngx_string("waf_shm_zone"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12,
      ngx_http_waf_set_shm_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL
    },
    {
      ngx_string("waf_json_log"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_waf_set_json_log,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL
    },
    {
      ngx_string("waf_json_log_level"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_waf_set_json_log_level,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL
    },

    /* M5运维指令（LOC级，可继承） */
    {
      ngx_string("waf"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, waf_enable),
      NULL
    },
    {
      ngx_string("waf_dynamic_block_enable"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, dyn_block_enable),
      NULL
    },

    /* M5全局运维指令（MAIN级，不可继承） */
    {
      ngx_string("waf_trust_xff"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, trust_xff),
      NULL
    },
    {
      ngx_string("waf_default_action"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_waf_set_default_action,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_waf_loc_conf_t, default_action),
      NULL
    },
    {
      ngx_string("waf_dynamic_block_score_threshold"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, dyn_block_threshold),
      NULL
    },
    {
      ngx_string("waf_dynamic_block_duration"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, dyn_block_duration),
      NULL
    },
    {
      ngx_string("waf_dynamic_block_window_size"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_waf_main_conf_t, dyn_block_window),
      NULL
    },

    ngx_null_command
};
/* clang-format on */

/* 解析并创建共享内存区域：waf_shm_zone <name> <size> */
static char *ngx_http_waf_set_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_waf_main_conf_t *mcf = conf;
  ngx_str_t *value;
  ngx_int_t size;
  ngx_shm_zone_t *zone;

  if (cf->args->nelts < 3) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: invalid args for waf_shm_zone, expect: <name> <size>");
    return NGX_CONF_ERROR;
  }

  value = cf->args->elts; /* [0]=directive, [1]=name, [2]=size */

  if (mcf->shm_zone != NULL) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "waf: waf_shm_zone duplicated");
    return NGX_CONF_ERROR;
  }

  if (value[1].len == 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "waf: shm name empty");
    return NGX_CONF_ERROR;
  }

  size = ngx_parse_size(&value[2]);
  if (size == NGX_ERROR || size <= 0) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "waf: invalid shm size %V", &value[2]);
    return NGX_CONF_ERROR;
  }

  zone = ngx_shared_memory_add(cf, &value[1], (size_t)size, &ngx_http_waf_module);
  if (zone == NULL) {
    return NGX_CONF_ERROR;
  }

  zone->init = waf_dyn_shm_zone_init;
  /* data 在 init 中设置为 shm 上下文；此处保留 main_conf 信息 */
  mcf->shm_zone = zone;
  mcf->shm_zone_name = value[1];
  mcf->shm_zone_size = (size_t)size;

  ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "waf: shm zone configured name=%V size=%uz", &value[1],
                     (size_t)size);

  (void)cmd;
  return NGX_CONF_OK;
}

/* 解析 waf_json_log 路径并展开为绝对路径（相对 Nginx Prefix） */
static char *ngx_http_waf_set_json_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_waf_main_conf_t *mcf = conf;
  ngx_str_t *value;


  if (cf->args->nelts != 2) {
    return "invalid number of arguments";
  }

  value = cf->args->elts;
  mcf->json_log_path = value[1];

  /* 支持 off 关闭：不注册 open_files，后续写入将跳过 */
  if (mcf->json_log_path.len == 3 && ngx_strncasecmp(mcf->json_log_path.data, (u_char*)"off", 3) == 0) {
    mcf->json_log_path.len = 0;
    mcf->json_log_path.data = NULL;
    mcf->json_log_of = NULL;
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "waf: json_log disabled by 'off'");
    (void)cmd;
    return NGX_CONF_OK;
  }

  /* 展开为绝对路径（相对于 Nginx Prefix） */
  if (ngx_conf_full_name(cf->cycle, &mcf->json_log_path, 0) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                     "waf: json_log_path configured: \"%V\"", &mcf->json_log_path);

  /* 注册到 open_files：由 master 打开，worker 复用 fd；支持 USR1 重新打开 */
  if (mcf->json_log_path.len != 0) {
    mcf->json_log_of = ngx_conf_open_file(cf->cycle, &mcf->json_log_path);
    if (mcf->json_log_of == NULL) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "waf: failed to register json_log to open_files: %V",
                         &mcf->json_log_path);
      return NGX_CONF_ERROR;
    }
    /* 具体 open 标志由 Nginx 在 master 阶段统一处理，这里无需设置 */
  }

  (void)cmd;
  return NGX_CONF_OK;
}

/* 解析 waf_json_log_level off|debug|info|alert|error */
static char *ngx_http_waf_set_json_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_waf_main_conf_t *mcf = conf;
  ngx_str_t *value;

  if (cf->args->nelts != 2) {
    return "invalid number of arguments";
  }

  value = cf->args->elts;
  ngx_str_t level_str = value[1];

  if (level_str.len == 3 && ngx_strncmp(level_str.data, "off", 3) == 0) {
    mcf->json_log_level = (ngx_uint_t)WAF_LOG_OFF;
  } else if (level_str.len == 5 && ngx_strncmp(level_str.data, "debug", 5) == 0) {
    mcf->json_log_level = (ngx_uint_t)WAF_LOG_DEBUG;
  } else if (level_str.len == 4 && ngx_strncmp(level_str.data, "info", 4) == 0) {
    mcf->json_log_level = (ngx_uint_t)WAF_LOG_INFO;
  } else if (level_str.len == 5 && ngx_strncmp(level_str.data, "alert", 5) == 0) {
    mcf->json_log_level = (ngx_uint_t)WAF_LOG_ALERT;
  } else if (level_str.len == 5 && ngx_strncmp(level_str.data, "error", 5) == 0) {
    mcf->json_log_level = (ngx_uint_t)WAF_LOG_ERROR;
  } else {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: invalid waf_json_log_level \"%V\", must be: off|debug|info|alert|error",
                       &level_str);
    return NGX_CONF_ERROR;
  }

  (void)cmd;
  return NGX_CONF_OK;
}

/* 自定义解析：waf_default_action block|log，允许同级覆盖（后定义生效） */
static char *ngx_http_waf_set_default_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_waf_loc_conf_t *lcf = conf;
  ngx_str_t *value;

  if (cf->args->nelts != 2) {
    return "invalid number of arguments";
  }

  value = cf->args->elts; /* [0]=directive, [1]=value */

  if (value[1].len == 5 && ngx_strncasecmp(value[1].data, (u_char *)"block", 5) == 0) {
    lcf->default_action = WAF_DEFAULT_ACTION_BLOCK;
  } else if (value[1].len == 3 && ngx_strncasecmp(value[1].data, (u_char *)"log", 3) == 0) {
    lcf->default_action = WAF_DEFAULT_ACTION_LOG;
  } else {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "waf: invalid waf_default_action \"%V\", must be: block|log",
                       &value[1]);
    return NGX_CONF_ERROR;
  }

  (void)cmd;
  return NGX_CONF_OK;
}

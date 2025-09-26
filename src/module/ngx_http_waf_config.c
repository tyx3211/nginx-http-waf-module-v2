#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_waf_module_v2.h"
#include <yyjson/yyjson.h>
#include "ngx_http_waf_compiler.h"
#include <stdlib.h>
#include "ngx_http_waf_dynamic_block.h"

/*
 * 指令与配置：create/merge 与命令表
 * 说明：将配置相关逻辑与模块骨架分离，保持层级清晰。
 */

extern ngx_module_t ngx_http_waf_module; /* 用于 merge 时获取 main_conf */

/* 前置声明：自定义指令处理函数（M2.5 共享内存创建） */
static char* ngx_http_waf_set_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* 主配置 */
void* ngx_http_waf_create_main_conf(ngx_conf_t *cf)
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
    mcf->json_log_level = 0; /* off */
    mcf->shm_zone_raw.len = 0;
    mcf->shm_zone_raw.data = NULL;
    mcf->shm_zone = NULL;
    mcf->shm_zone_name.len = 0;
    mcf->shm_zone_name.data = NULL;
    mcf->shm_zone_size = 0;
	return mcf;
}

char* ngx_http_waf_init_main_conf(ngx_conf_t *cf, void *conf)
{
	(void)cf;
	(void)conf;
	/* 允许 0（不限）；>0 原样保留 */
	return NGX_CONF_OK;
}

/* loc 配置 */
void* ngx_http_waf_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_waf_loc_conf_t *lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
	if (lcf == NULL) {
		return NULL;
	}
	lcf->json_extends_max_depth = NGX_CONF_UNSET_UINT;
	lcf->rules_json_path.len = 0;
	lcf->rules_json_path.data = NULL;
	lcf->rules_doc = NULL;
	return lcf;
}

char* ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_waf_loc_conf_t *prev = parent;
	ngx_http_waf_loc_conf_t *conf = child;

	ngx_http_waf_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

	ngx_conf_merge_uint_value(conf->json_extends_max_depth,
				      prev->json_extends_max_depth,
				      mcf ? mcf->json_extends_max_depth : WAF_JSON_MAX_EXTENDS_DEPTH);

	if (conf->rules_json_path.len == 0 && prev->rules_json_path.len != 0) {
		conf->rules_json_path = prev->rules_json_path;
	}

	/* 合并完成后按最终 max_depth 尝试解析规则（存根：仅调用接口并记录错误） */
	if (conf->rules_json_path.len != 0) {
		ngx_http_waf_json_error_t err;
		err.file.len = 0; err.file.data = NULL;
		err.json_pointer.len = 0; err.json_pointer.data = NULL;
		err.message.len = 0; err.message.data = NULL;

		conf->rules_doc = ngx_http_waf_json_load_and_merge(cf->pool,
							   cf->log,
							   (mcf && mcf->jsons_dir.len != 0) ? &mcf->jsons_dir : NULL,
							   &conf->rules_json_path,
							   conf->json_extends_max_depth,
							   &err);
		if (conf->rules_doc == NULL) {
			ngx_log_error(NGX_LOG_ERR, cf->log, 0,
				      "waf: failed to load rules_json %V: file=%V ptr=%V msg=%V",
				      &conf->rules_json_path, &err.file, &err.json_pointer, &err.message);
			return NGX_CONF_ERROR;
		}
		else {
			yyjson_val* root = yyjson_doc_get_root(conf->rules_doc);
			yyjson_val* rules = root ? yyjson_obj_get(root, "rules") : NULL;
			size_t cnt = (rules && yyjson_is_arr(rules)) ? yyjson_arr_size(rules) : 0;
			ngx_log_error(NGX_LOG_INFO, cf->log, 0,
				      "waf: merged rules %uz from %V (depth=%ui)",
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
				ngx_log_error(NGX_LOG_WARN, cf->log, 0, "waf: final_doc dump failed: code=%ui", (ngx_uint_t)werr.code);
			}
			#endif

			/* M2：调用编译器生成只读快照并挂载到 lcf */
			{
				waf_compiled_snapshot_t* snap = NULL;
				ngx_http_waf_json_error_t c_err;
				c_err.file.len = 0; c_err.file.data = NULL;
				c_err.json_pointer.len = 0; c_err.json_pointer.data = NULL;
				c_err.message.len = 0; c_err.message.data = NULL;
				if (ngx_http_waf_compile_rules(cf->pool, cf->log, conf->rules_doc, &snap, &c_err) != NGX_OK) {
					ngx_log_error(NGX_LOG_ERR, cf->log, 0,
						      "waf: compile failed: file=%V ptr=%V msg=%V",
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
		ngx_conf_set_str_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_waf_main_conf_t, json_log_path),
		NULL
	},
	{
		ngx_string("waf_json_log_level"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_waf_main_conf_t, json_log_level),
		NULL
	},
	ngx_null_command
};


/* 解析并创建共享内存区域：waf_shm_zone <name> <size> */
static char*
ngx_http_waf_set_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_waf_main_conf_t *mcf = conf;
    ngx_str_t       *value;
    ngx_int_t        size;
    ngx_shm_zone_t  *zone;

    if (cf->args->nelts < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid args for waf_shm_zone, expect: <name> <size>");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts; /* [0]=directive, [1]=name, [2]=size */

    if (mcf->shm_zone != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: waf_shm_zone duplicated");
        return NGX_CONF_ERROR;
    }

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: shm name empty");
        return NGX_CONF_ERROR;
    }

    size = ngx_parse_size(&value[2]);
    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "waf: invalid shm size %V", &value[2]);
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

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "waf: shm zone configured name=%V size=%uz", &value[1], (size_t)size);

    (void)cmd;
    return NGX_CONF_OK;
}


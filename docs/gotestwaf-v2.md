### v2 gotestwaf 使用指引

> 目的：复用 v1 的 gotestwaf 测试流程，但使用 v2 JSON 规则与指令。

#### 1. 布署准备
- 规则目录：将 `WAF_RULES_JSON/` 整体放到 `${NGINX_PREFIX}/WAF_RULES_JSON`（本项目软链 `nginx-install` 指向 `/usr/local/nginx`）。
- 入口规则：已提供 `WAF_RULES_JSON/user/gotestwaf_user_rules.json`，继承全部核心规则（SQLi/XSS/目录遍历/LFI/RCE/UA）。
- Nginx 配置：使用 `docs/gotestwaf.nginx.conf`（动态模块 `ngx_http_waf_module.so` 需已安装到 `${NGINX_PREFIX}/modules/`）。

#### 2. 启动示例
```bash
# 假设已在 /usr/local/nginx 下
sudo /usr/local/nginx/sbin/nginx -c /path/to/repo/nginx-http-waf-module-v2/docs/gotestwaf.nginx.conf
```
- 核心指令要点：`waf_jsons_dir WAF_RULES_JSON;`（相对 Nginx Prefix），`waf_rules_json user/gotestwaf_user_rules.json;`，`waf_dynamic_block_enable off;` 避免影响评分。
- JSONL 日志：默认写入 `${NGINX_PREFIX}/logs/waf.jsonl`。

#### 3. 运行 gotestwaf
```bash
gotestwaf --url http://localhost:8080/ \
  --blockStatusCodes 403 \
  --testCasesPath ./gotestwaf_testcases/   # 按需替换路径
```
可结合 `--reportPath` 输出报告；若在远端主机运行，请替换目标 URL。

#### 4. 常见问题
- 路径解析：`waf_jsons_dir` 相对路径基于 Nginx Prefix；`waf_rules_json` 的非 `./`/`../` 相对路径基于 `waf_jsons_dir`。
- 规则调整：如需增删规则，可在 `user/gotestwaf_user_rules.json` 中追加自定义 `rules`，或通过 `meta.extends` 额外继承其它文件。



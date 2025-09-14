## clangd 开发环境快速指引（compile_commands.json 生成）

本指引帮助在 v2 新目录下生成 `compile_commands.json`，便于 clangd 正确识别头文件与符号。

前提：
- 系统已安装 `bear`, `build-essential`, `libpcre3-dev`, `zlib1g-dev`, `libssl-dev`；
- 已准备好 Nginx 源码（建议 `nginx-1.24.0`）。
- v2 目录将作为 `--add-dynamic-module` 的目标，需要存在 `config` 与最小骨架（源/头文件可以是空实现）。

目录假设：
- Nginx 源码目录：`/home/william/myNginxWorkspace/nginx-src/nginx-1.24.0`
- v2 模块目录：`/home/william/myNginxWorkspace/nginx-http-waf-module-v2`

步骤：
1) 进入 Nginx 源码目录：
```bash
cd /home/william/myNginxWorkspace/nginx-src/nginx-1.24.0
```

2) 配置构建（启用调试与兼容动态模块）：
```bash
./configure \
  --prefix=/usr/local/nginx \
  --with-debug \
  --with-compat \
  --add-dynamic-module=../nginx-http-waf-module-v2
```

3) 使用 bear 生成编译数据库：
```bash
bear -- make modules -j"$(nproc)"
```

4) 建立符号链接方便 clangd：
```bash
ln -sf /home/william/myNginxWorkspace/nginx-src/nginx-1.24.0/compile_commands.json \
       /home/william/myNginxWorkspace/nginx-http-waf-module-v2/
```

注意：
- 若 v2 尚无最小骨架或缺少 `config`，`make modules` 可能失败。可先创建空实现文件与头文件以通过编译阶段；
- v2 的 `config` 需包含以下 `-I` 路径，clangd 才能识别：
  - `-I$ngx_addon_dir/src/include`
  - `-I$ngx_addon_dir/third_party/yyjson`
  - `-I$ngx_addon_dir/third_party/uthash`

脚本化：
- 可运行 `dev/setup-clangd.sh`（见 v2 根目录下 `dev/`）自动完成上述步骤。

故障排查：
- clangd 找不到头文件：确认 `compile_commands.json` 已生成并链接到 v2 根；确认 `config` 含有正确 `-I` 路径；
- `make modules` 报错：通常为 v2 缺少最小骨架或 `config` 未就绪；按重构文档先创建骨架与 `config`。



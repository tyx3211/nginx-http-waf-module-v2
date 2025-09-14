v2

### 里程碑

详细的阶段目标、范围与完成定义请见：`docs/milestones.md`。

### 快速开始（构建/加载 v2 动态模块）

以下步骤帮助你在本地快速编译并加载 v2 模块，便于验证工具链与开发环境：

1) 安装依赖（Ubuntu 示例）：
```bash
sudo apt update
sudo apt install -y build-essential libpcre3-dev zlib1g-dev libssl-dev bear curl
```

2) 生成编译数据库供 clangd 使用：
```bash
bash dev/setup-clangd.sh
```
执行完成后，v2 根目录应出现/指向 `compile_commands.json`。

3) 在 Nginx 源码目录构建动态模块（可选，脚本已包含构建）：
```bash
cd /home/william/myNginxWorkspace/nginx-src/nginx-1.24.0
make modules -j"$(nproc)"
```
构建成功后，动态模块通常位于：
```
objs/ngx_http_waf_module.so
```

4) 在 nginx.conf 加载模块（示例）：
```
load_module  modules/ngx_http_waf_module.so;
```
注意：路径按你的安装/拷贝位置调整。

5) 启动/验证：
```bash
nginx -t
nginx -s reload || sudo nginx
```
若 `nginx -t` 通过，则表示模块已能被 Nginx 正常识别。

提示：
- v2 当前是最小骨架实现，尚未注册处理逻辑；该阶段主要用于打通编译链与 IDE 语义跳转。
- 若 `bear` 或下载工具缺失，请先安装；脚本会给出明确报错信息。
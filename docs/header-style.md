## 头文件引入与目录分层规范（强制）

### 目标
- 消除相对路径 include，统一由构建脚本提供包含路径；明确内部公共/私有边界，减少耦合与编译时间。

### 基本规则
- 禁止使用以 `./` 或 `../` 开头的相对路径 include。
- 第三方库：使用尖括号并带库前缀，例如 `<yyjson/yyjson.h>`、`<uthash/uthash.h>`。
- 内部头：使用引号且不带目录名，例如 `"ngx_http_waf_action.h"`；通过 `-I$ngx_addon_dir/src/include` 解析。
- 每个头文件使用 `#pragma once` 或 include guard（注意：include guard必需，`#pragma once` 可选）。

### 目录分层
- `src/include/`：内部公共头（跨目录可见的声明、枚举、对外结构）。
- `src/*/`：实现及私有头。若某实现细节只在单目录内使用，则将其放在该目录，不放入 `src/include/`。

### 拆分建议（公共 API 与内部细节）
- 当某模块需要被跨目录引用时：
  - 在 `src/include/` 新建最小公共头，仅包含前置声明、对外函数原型与必要类型别名。
  - 在实现目录保留 `_internal.h`（如 `ngx_http_waf_dynamic_block_internal.h`）存放结构体细节与仅内部可见声明。

### 构建与工具链
- 在模块 `config` 中确保：`CFLAGS+=" -I$ngx_addon_dir/src/include -I$ngx_addon_dir/third_party/yyjson -I$ngx_addon_dir/third_party/uthash"`。
- clangd：通过 `compile_commands.json` 解析上述 `-I`，无需在源码中写目录前缀。

### 示例
```c
// 正确：内部头
#include "ngx_http_waf_dynamic_block.h"

// 正确：第三方
#include <yyjson/yyjson.h>

// 错误：相对路径
// #include "../core/ngx_http_waf_dynamic_block.h"
// #include "src/include/ngx_http_waf_action.h"
```

### 禁止的做法
- 在实现目录放置同名“跳板头”并通过相对路径再包含真正头（会被就近规则优先命中）。
- 在源码中硬编码 `src/include/` 或其他目录名。

### 迁移策略
- 新增公共头到 `src/include/`；将源文件中的 `#include` 改为无目录名形式。
- 清理/删除实现目录中与公共头同名的跳板头。










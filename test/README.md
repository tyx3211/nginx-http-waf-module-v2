# WAF v2 测试套件

## 测试策略

### 第一阶段：编译验证
- [x] 基础编译测试（smoke test）
- [ ] Nginx模块编译测试
- [ ] 配置指令解析测试

### 第二阶段：功能测试
- [ ] JSON规则加载测试
- [ ] 规则匹配测试（SQLi/XSS）
- [ ] IP黑白名单测试
- [ ] 动态封禁测试
- [ ] JSONL日志输出测试

### 第三阶段：集成测试
- [ ] 端到端请求测试
- [ ] 性能基准测试
- [ ] 并发安全测试

## 测试文件

- `test_compiler.c` - 编译器单元测试（基础）
- `test_nginx_integration.sh` - Nginx集成测试脚本
- `test_rules/` - 测试用规则集
- `test_requests/` - 测试用HTTP请求

## 运行测试

```bash
# 单元测试
gcc test/test_compiler.c -o test/test_compiler && ./test/test_compiler

# 集成测试
./test/test_nginx_integration.sh

# 全部测试
make test
```




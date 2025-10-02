#!/bin/bash

# 格式化脚本 - 将 nginx-http-waf-module-v2 项目中的C/C++源代码格式化为2空格缩进
# 使用 clang-format 工具

# 设置项目目录
PROJECT_DIR="/home/william/myNginxWorkspace/nginx-http-waf-module-v2"
cd "$PROJECT_DIR"

# 检查 clang-format 是否安装
if ! command -v clang-format &> /dev/null; then
    echo "错误: clang-format 未安装"
    echo "请运行以下命令安装："
    echo "  sudo apt-get install clang-format"
    exit 1
fi

echo "开始格式化 nginx-http-waf-module-v2 项目中的C/C++源文件..."
echo "使用配置文件: $PROJECT_DIR/.clang-format"

# 计数器
count=0

# 查找并格式化所有C/C++源文件
find . -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.cc" -o -name "*.cxx" -o -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) \
    -not -path "./third_party/*" \
    -not -path "./.cache/*" | while read -r file; do
    
    echo "格式化: $file"
    clang-format -i -style=file "$file"
    ((count++))
done

echo "格式化完成！"

# 显示一些统计信息
echo ""
echo "项目中的C/C++源文件统计："
find . -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.cc" -o -name "*.cxx" -o -name "*.h" -o -name "*.hpp" -o -name "*.hxx" \) \
    -not -path "./third_party/*" \
    -not -path "./.cache/*" | wc -l | xargs echo "总文件数:"

# 验证格式化结果的示例
echo ""
echo "验证格式化结果 - 检查缩进是否为2空格："
if [ -f "src/module/ngx_http_waf_module.c" ]; then
    echo "文件: src/module/ngx_http_waf_module.c 的前20行："
    head -20 "src/module/ngx_http_waf_module.c" | cat -A
fi

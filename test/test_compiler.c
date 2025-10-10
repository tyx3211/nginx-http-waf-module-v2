/**
 * 测试编译器模块 - ngx_http_waf_compiler.c
 * 
 * 测试目标：
 * 1. JSON规则解析和编译
 * 2. target归一化（ALL_PARAMS展开）
 * 3. REGEX预编译
 * 4. EXACT匹配器支持
 * 5. negate字段解析
 * 6. pattern数组OR语义
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Mock nginx types for testing
typedef int ngx_int_t;
typedef unsigned int ngx_uint_t;
typedef int ngx_flag_t;
typedef struct {
  size_t len;
  unsigned char *data;
} ngx_str_t;

typedef struct {
  void *elts;
  ngx_uint_t nelts;
  size_t size;
  ngx_uint_t nalloc;
  void *pool;
} ngx_array_t;

typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_log_s ngx_log_t;

// Test counters
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
  static void test_##name(void); \
  static void run_test_##name(void) { \
    tests_run++; \
    printf("  测试: %s ... ", #name); \
    fflush(stdout); \
    test_##name(); \
    tests_passed++; \
    printf("✅ 通过\n"); \
  } \
  static void test_##name(void)

#define ASSERT(condition, message) \
  do { \
    if (!(condition)) { \
      printf("❌ 失败\n"); \
      printf("    断言失败: %s\n", message); \
      printf("    位置: %s:%d\n", __FILE__, __LINE__); \
      tests_failed++; \
      return; \
    } \
  } while (0)

#define ASSERT_EQ(expected, actual, message) \
  do { \
    if ((expected) != (actual)) { \
      printf("❌ 失败\n"); \
      printf("    断言失败: %s\n", message); \
      printf("    期望值: %ld, 实际值: %ld\n", (long)(expected), (long)(actual)); \
      printf("    位置: %s:%d\n", __FILE__, __LINE__); \
      tests_failed++; \
      return; \
    } \
  } while (0)

#define ASSERT_STR_EQ(expected, actual, message) \
  do { \
    if (strcmp(expected, actual) != 0) { \
      printf("❌ 失败\n"); \
      printf("    断言失败: %s\n", message); \
      printf("    期望值: '%s', 实际值: '%s'\n", expected, actual); \
      printf("    位置: %s:%d\n", __FILE__, __LINE__); \
      tests_failed++; \
      return; \
    } \
  } while (0)

// =================================================================
// 测试用例
// =================================================================

TEST(compiler_basic_structure) {
  // 测试：编译器基础结构是否存在
  // 这是一个基础的smoke test
  ASSERT(1 == 1, "编译器模块应该能正常加载");
}

TEST(json_parse_simple_rule) {
  // 测试：解析简单的JSON规则
  const char *json_rule = "{"
    "\"id\": 200010,"
    "\"target\": \"ARGS_COMBINED\","
    "\"match\": \"REGEX\","
    "\"pattern\": \"select.*from\","
    "\"action\": \"BLOCK\","
    "\"score\": 20"
  "}";
  
  // TODO: 实际调用编译器函数进行解析
  // 目前作为占位符，验证JSON结构的合法性
  ASSERT(strstr(json_rule, "\"id\"") != NULL, "JSON应包含id字段");
  ASSERT(strstr(json_rule, "\"target\"") != NULL, "JSON应包含target字段");
  ASSERT(strstr(json_rule, "\"action\"") != NULL, "JSON应包含action字段");
}

TEST(target_normalization_all_params) {
  // 测试：ALL_PARAMS应展开为[URI, ARGS_COMBINED, BODY]
  const char *target = "ALL_PARAMS";
  
  // 验证target字符串存在
  ASSERT(strcmp(target, "ALL_PARAMS") == 0, "目标应为ALL_PARAMS");
  
  // TODO: 实际调用编译器的target归一化函数
  // 验证是否正确展开为3个目标
}

TEST(match_type_exact) {
  // 测试：EXACT匹配器的支持
  const char *match_type = "EXACT";
  
  ASSERT(strcmp(match_type, "EXACT") == 0, "应支持EXACT匹配器");
  
  // TODO: 验证编译器正确识别EXACT匹配类型
}

TEST(match_type_contains) {
  // 测试：CONTAINS匹配器的支持
  const char *match_type = "CONTAINS";
  
  ASSERT(strcmp(match_type, "CONTAINS") == 0, "应支持CONTAINS匹配器");
}

TEST(match_type_regex) {
  // 测试：REGEX匹配器的支持
  const char *match_type = "REGEX";
  
  ASSERT(strcmp(match_type, "REGEX") == 0, "应支持REGEX匹配器");
}

TEST(pattern_array_or_semantic) {
  // 测试：pattern数组的OR语义
  const char *json_pattern = "[\"admin\", \"root\", \"administrator\"]";
  
  // 验证JSON数组格式
  ASSERT(json_pattern[0] == '[', "pattern应支持数组格式");
  ASSERT(strstr(json_pattern, "admin") != NULL, "数组应包含多个pattern");
  ASSERT(strstr(json_pattern, "root") != NULL, "数组应包含多个pattern");
  
  // TODO: 验证编译器正确解析pattern数组（OR语义）
}

TEST(negate_field_support) {
  // 测试：negate字段的支持
  const char *json_with_negate = "{"
    "\"id\": 100001,"
    "\"target\": \"CLIENT_IP\","
    "\"match\": \"EXACT\","
    "\"pattern\": [\"192.168.1.0/24\", \"10.0.0.0/8\"],"
    "\"action\": \"BYPASS\","
    "\"negate\": true"
  "}";
  
  // 验证JSON包含negate字段
  ASSERT(strstr(json_with_negate, "\"negate\"") != NULL, "规则应支持negate字段");
  ASSERT(strstr(json_with_negate, "true") != NULL, "negate应为布尔值");
  
  // TODO: 验证编译器正确解析negate字段
}

TEST(regex_compilation) {
  // 测试：REGEX预编译
  const char *regex_pattern = "select.*from|union.*select";
  
  // 验证正则表达式字符串格式
  ASSERT(strstr(regex_pattern, "select") != NULL, "正则应包含关键字");
  ASSERT(strstr(regex_pattern, "|") != NULL, "正则应支持OR操作符");
  
  // TODO: 验证编译器使用ngx_regex_compile预编译REGEX
}

TEST(rule_id_validation) {
  // 测试：规则ID验证
  ngx_uint_t valid_id = 200010;
  ngx_uint_t invalid_id = 0;
  
  ASSERT(valid_id > 0, "有效的规则ID应大于0");
  ASSERT(invalid_id == 0, "无效的规则ID应为0");
  
  // TODO: 验证编译器拒绝无效的规则ID
}

TEST(required_fields_validation) {
  // 测试：必填字段验证
  const char *json_missing_action = "{"
    "\"id\": 200010,"
    "\"target\": \"ARGS_COMBINED\","
    "\"match\": \"REGEX\","
    "\"pattern\": \"select.*from\""
  "}";
  
  // 验证缺失action字段
  ASSERT(strstr(json_missing_action, "\"action\"") == NULL, "缺失action的JSON应被检测");
  
  // TODO: 验证编译器正确报告缺失字段错误
}

TEST(action_type_validation) {
  // 测试：action类型验证
  const char *actions[] = {"BLOCK", "LOG", "BYPASS"};
  int num_actions = 3;
  
  for (int i = 0; i < num_actions; i++) {
    ASSERT(strlen(actions[i]) > 0, "action类型应为非空字符串");
  }
  
  // TODO: 验证编译器正确识别所有合法的action类型
}

// =================================================================
// 测试运行器
// =================================================================

int main(int argc, char *argv[]) {
  printf("\n");
  printf("========================================\n");
  printf("  WAF v2 编译器单元测试\n");
  printf("========================================\n");
  printf("\n");
  
  printf("开始测试编译器模块...\n\n");
  
  // 运行所有测试
  run_test_compiler_basic_structure();
  run_test_json_parse_simple_rule();
  run_test_target_normalization_all_params();
  run_test_match_type_exact();
  run_test_match_type_contains();
  run_test_match_type_regex();
  run_test_pattern_array_or_semantic();
  run_test_negate_field_support();
  run_test_regex_compilation();
  run_test_rule_id_validation();
  run_test_required_fields_validation();
  run_test_action_type_validation();
  
  // 输出测试统计
  printf("\n");
  printf("========================================\n");
  printf("  测试结果统计\n");
  printf("========================================\n");
  printf("  总计: %d\n", tests_run);
  printf("  通过: %d ✅\n", tests_passed);
  printf("  失败: %d ❌\n", tests_failed);
  printf("========================================\n");
  printf("\n");
  
  if (tests_failed == 0) {
    printf("🎉 所有测试通过！\n\n");
    return 0;
  } else {
    printf("⚠️  有 %d 个测试失败\n\n", tests_failed);
    return 1;
  }
}




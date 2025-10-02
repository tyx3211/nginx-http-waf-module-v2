#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson/yyjson.h>

int main(void)
{
  const char *json =
      "// comment\n{\n  'a': 1, // trailing comma\n  'b': [1,2,3,],\n}\n";
  yyjson_read_flag flg =
      0 | YYJSON_READ_ALLOW_COMMENTS | YYJSON_READ_ALLOW_TRAILING_COMMAS |
      YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_UNQUOTED_KEY |
      YYJSON_READ_ALLOW_EXT_WHITESPACE | YYJSON_READ_ALLOW_EXT_ESCAPE;
  yyjson_read_err err;
  yyjson_doc *doc =
      yyjson_read_opts((char *)json, strlen(json), flg, NULL, &err);
  if (!doc) {
    fprintf(stderr, "parse failed: %s at %zu\n", err.msg ? err.msg : "unknown",
            err.pos);
    return 1;
  }
  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *a = yyjson_obj_get(root, "a");
  long long aval = a ? yyjson_get_sint(a) : -1;
  printf("a=%lld\n", aval);
  yyjson_doc_free(doc);
  return 0;
}

#ifndef _NGX_HTTP_WAF_STAGE_H_INCLUDED_
#define _NGX_HTTP_WAF_STAGE_H_INCLUDED_

#include "ngx_http_waf_types.h"
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * STAGE 宏：仅根据阶段返回的 waf_rc_e 统一映射为 Nginx rc，
 * 不做任何日志 flush；BLOCK/BYPASS 的最终落盘由 action 层完成，
 * ALLOW 的最终落盘由 handler 尾部调用 waf_log_flush_final 完成。
 */
#define WAF_STAGE(ctx, CALL)                               \
  do {                                                     \
    waf_rc_e _waf_rc = (CALL);                             \
    if (_waf_rc == WAF_RC_ASYNC) {                         \
      return NGX_DONE;                                     \
    }                                                      \
    if (_waf_rc == WAF_RC_BLOCK) {                         \
      return (ctx)->final_status > 0 ? (ctx)->final_status \
                                     : NGX_HTTP_FORBIDDEN; \
    }                                                      \
    if (_waf_rc == WAF_RC_BYPASS) {                        \
      return NGX_DECLINED;                                 \
    }                                                      \
    if (_waf_rc == WAF_RC_ERROR) {                         \
      return NGX_HTTP_INTERNAL_SERVER_ERROR;               \
    }                                                      \
  } while (0)

#endif /* _NGX_HTTP_WAF_STAGE_H_INCLUDED_ */

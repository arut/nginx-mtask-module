#ifndef __NGX_HTTP_MTASK_H__
#define __NGX_HTTP_MTASK_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef ngx_int_t (*ngx_http_mtask_handler_pt)(ngx_http_request_t*, ngx_chain_t**);

struct ngx_http_mtask_loc_conf_s {

	ngx_http_mtask_handler_pt handler;

	size_t stack_size;

	ngx_msec_t timeout;
};

typedef struct ngx_http_mtask_loc_conf_s ngx_http_mtask_loc_conf_t;

extern ngx_module_t ngx_http_mtask_module;

#endif /* __NGX_HTTP_MTASK_H__ */

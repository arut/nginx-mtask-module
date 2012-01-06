/******************************************************************************
Copyright (c) 2011-2012, Roman Arutyunyan (arut@qip.ru)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, 
      this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.
*******************************************************************************/

/*
   Example of using nginx-mtask-module: upstream module
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_mtask_module.h>

static char * ngx_http_mtask_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_mtask_upstream_commands[] = {

	/* TODO: add address & port here */

	{	ngx_string("mtask_proxy_pass"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
		ngx_http_mtask_upstream,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL },

	ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_mtask_upstream_module_ctx = {

	NULL,                               /* preconfiguration */
	NULL,                               /* postconfiguration */
	NULL,                               /* create main configuration */
	NULL,                               /* init main configuration */
	NULL,                               /* create server configuration */
	NULL,                               /* merge server configuration */
	NULL,                               /* create location configuration */
	NULL                                /* merge location configuration */
};

/* Module */
ngx_module_t ngx_http_mtask_upstream_module = {

	NGX_MODULE_V1,
	&ngx_http_mtask_upstream_module_ctx,/* module context */
	ngx_http_mtask_upstream_commands,   /* module directives */
	NGX_HTTP_MODULE,                    /* module type */
	NULL,                               /* init master */
	NULL,                               /* init module */
	NULL,                               /* init process */
	NULL,                               /* init thread */
	NULL,                               /* exit thread */
	NULL,                               /* exit process */
	NULL,                               /* exit master */
	NGX_MODULE_V1_PADDING
};

#define BUFSIZE 1024

ngx_int_t ngx_http_mtask_upstream_handler(ngx_http_request_t *r, ngx_chain_t *out) {

	int s;
	struct sockaddr_in addr;
	ssize_t sz;
	ngx_buf_t *b;

	s = socket(AF_INET, SOCK_STREAM, 0);

	if (s == -1)
		return NGX_ERROR;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(1979);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(s, &addr, sizeof(addr)) == -1) {

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask upstream connect() failed");
		
		close(s);
		
		return NGX_ERROR;
	}

	out->buf = ngx_create_temp_buf(r->pool, BUFSIZE);
	out->next = NULL;

	for(;;) {

		b = out->buf;

		sz = recv(s, b->last, b->end - b->last, 0);

		if (sz == -1) {

			ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
					"mtask upstream recv() failed");

			close(s);

			return NGX_ERROR;
		}

		if (!sz)
			break;

		b->last += sz;

		if (b->last == b->end) {
			out->next = (ngx_chain_t*)ngx_palloc(r->pool, sizeof(ngx_chain_t));
			out = out->next;
			out->next = NULL;
			out->buf = ngx_create_temp_buf(r->pool, BUFSIZE);
		}
	}

	close(s);

	out->buf->last_buf = 1;

	return NGX_OK;
}

static char * ngx_http_mtask_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mtask_loc_conf_t *mlcf = conf;

	mlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_mtask_module);

	mlcf->handler = &ngx_http_mtask_upstream_handler;

	return NGX_CONF_OK;
}


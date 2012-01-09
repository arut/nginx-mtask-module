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
   Example of using nginx-mtask-module: TCP-to-HTTP upstream module
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ctype.h>

#include <ngx_http_mtask_module.h>

static char* ngx_http_mtask_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void* ngx_http_mtask_upstream_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_mtask_upstream_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

struct ngx_http_mtask_upstream_loc_conf_s {

	struct sockaddr_in addr;
};

typedef struct ngx_http_mtask_upstream_loc_conf_s ngx_http_mtask_upstream_loc_conf_t;

static ngx_command_t ngx_http_mtask_upstream_commands[] = {

	{	ngx_string("mtask_proxy_pass"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
		ngx_http_mtask_upstream,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL },

	ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_mtask_upstream_module_ctx = {

	NULL,                                      /* preconfiguration */
	NULL,                                      /* postconfiguration */
	NULL,                                      /* create main configuration */
	NULL,                                      /* init main configuration */
	NULL,                                      /* create server configuration */
	NULL,                                      /* merge server configuration */
	ngx_http_mtask_upstream_create_loc_conf,   /* create location configuration */
	ngx_http_mtask_upstream_merge_loc_conf     /* merge location configuration */
};

/* Module */
ngx_module_t ngx_http_mtask_upstream_module = {

	NGX_MODULE_V1,
	&ngx_http_mtask_upstream_module_ctx,       /* module context */
	ngx_http_mtask_upstream_commands,          /* module directives */
	NGX_HTTP_MODULE,                           /* module type */
	NULL,                                      /* init master */
	NULL,                                      /* init module */
	NULL,                                      /* init process */
	NULL,                                      /* init thread */
	NULL,                                      /* exit thread */
	NULL,                                      /* exit process */
	NULL,                                      /* exit master */
	NGX_MODULE_V1_PADDING
};

#define BUFSIZE 1024

ngx_int_t ngx_http_mtask_upstream_handler(ngx_http_request_t *r, ngx_chain_t **out) {

	int s;
	struct sockaddr_in addr;
	ssize_t sz;
	ngx_buf_t *b;
	ngx_http_mtask_upstream_loc_conf_t *mulcf;
	ngx_chain_t *node;

	mulcf = ngx_http_get_module_loc_conf(r, ngx_http_mtask_upstream_module);

	s = socket(AF_INET, SOCK_STREAM, 0);

	if (s == -1)
		return NGX_ERROR;

	if (connect(s, &mulcf->addr, sizeof(addr)) == -1) {

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask upstream connect() failed");
		
		close(s);
		
		return NGX_ERROR;
	}

	node = ngx_palloc(r->pool, sizeof(ngx_chain_t));
	node->buf = ngx_create_temp_buf(r->pool, BUFSIZE);
	node->next = NULL;

	*out = node;

	for(;;) {

		b = node->buf;

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
			node->next = (ngx_chain_t*)ngx_palloc(r->pool, sizeof(ngx_chain_t));
			node = node->next;
			node->next = NULL;
			node->buf = ngx_create_temp_buf(r->pool, BUFSIZE);
		}
	}

	close(s);

	node->buf->last_buf = 1;

	return NGX_OK;
}

static void* ngx_http_mtask_upstream_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mtask_upstream_loc_conf_t *conf = ngx_pcalloc(cf->pool, 
			sizeof(ngx_http_mtask_upstream_loc_conf_t));

	return conf;
}

static char* ngx_http_mtask_upstream_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mtask_upstream_loc_conf_t *prev = parent;
	ngx_http_mtask_upstream_loc_conf_t *conf = child;

	if (prev->addr.sin_port && !conf->addr.sin_port)
		conf->addr = prev->addr;

	return NGX_CONF_OK;
}


static char * ngx_http_mtask_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mtask_loc_conf_t *mlcf = conf;
	ngx_http_mtask_upstream_loc_conf_t *mulcf;
	ngx_str_t *value;
	struct hostent *h;
	char addr[16];
	size_t n;

	mlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_mtask_module);

	mlcf->handler = &ngx_http_mtask_upstream_handler;

	mulcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_mtask_upstream_module);

	value = cf->args->elts;

	mulcf->addr.sin_family = AF_INET;
	mulcf->addr.sin_port = htons(ngx_atoi(value[2].data, value[2].len));

	if (value[1].len 
			&& isdigit(value[1].data[value[1].len - 1])) {

		/* ip */

		n = value[1].len;
		if (n > 15)
			return "has bad long address";

		strncpy(addr, (const char*)value[1].data, value[1].len);
		addr[value[1].len] = 0;

		if (!inet_aton(addr, &mulcf->addr.sin_addr))
			return "has bad address";
	
	} else {

		/* domain */

		h = gethostbyname((const char*)value[1].data);

		if (h == NULL)
			return "failed ro resolve domain";

		memcpy(&mulcf->addr.sin_addr, h->h_addr, h->h_length);
	}

	return NGX_CONF_OK;
}


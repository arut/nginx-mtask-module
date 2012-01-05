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
 NGINX module providing userspace cooperative multitasking 
 for IO-bound content handlers
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ucontext.h>
#include <dlfcn.h>

/* NB: NGINX logger is greedy of stack; use > 4k for safety */
#define MTASK_DEFAULT_STACK_SIZE 16384

#define MTASK_DEFAULT_TIMEOUT 10000

static char * ngx_http_mtask(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void* ngx_http_mtask_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_mtask_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

typedef ngx_int_t (*ngx_http_mtask_handler_pt)(ngx_http_request_t*, ngx_chain_t*);

struct ngx_http_mtask_loc_conf_s {

	ngx_http_mtask_handler_pt handler;

	size_t stack_size;

	ngx_msec_t timeout;
};

typedef struct ngx_http_mtask_loc_conf_s ngx_http_mtask_loc_conf_t;

struct ngx_http_mtask_ctx_s {

	/* current handler contexts: wake & return */
	ucontext_t wctx, rctx;

	int timedout;
};

typedef struct ngx_http_mtask_ctx_s ngx_http_mtask_ctx_t;

/* Module commands */

static ngx_command_t ngx_http_mtask_commands[] = {

	{	ngx_string("mtask"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
		ngx_http_mtask,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL },

	{	ngx_string("mtask_stack"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_mtask_loc_conf_t, stack_size),
		NULL },

	{   ngx_string("mtask_timeout"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_mtask_loc_conf_t, timeout),
		NULL },

	ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_mtask_module_ctx = {

	NULL,                               /* preconfiguration */
	NULL,                               /* postconfiguration */
	NULL,                               /* create main configuration */
	NULL,                               /* init main configuration */
	NULL,                               /* create server configuration */
	NULL,                               /* merge server configuration */
	ngx_http_mtask_create_loc_conf,     /* create location configuration */
	ngx_http_mtask_merge_loc_conf       /* merge location configuration */
};

/* Module */
ngx_module_t ngx_http_mtask_module = {

	NGX_MODULE_V1,
	&ngx_http_mtask_module_ctx,         /* module context */
	ngx_http_mtask_commands,            /* module directives */
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

ngx_int_t test_mtask_handler(ngx_http_request_t *r, ngx_chain_t *out) {

	int s;
	struct sockaddr_in addr;
	char buf[1024];
	ssize_t sz;

#if 0
	strcpy(buf, "fast result");
	sz = strlen(buf);
	out->buf = ngx_create_temp_buf(r->pool, sz);
	memcpy(out->buf->pos, buf, sz);
	out->buf->last += sz;
	out->next = NULL;
	out->buf->last_buf = 1;
	return NGX_OK;
#endif

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == -1)
		return NGX_ERROR;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(1979);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(s, &addr, sizeof(addr)) == -1) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask test connect() failed");
		return NGX_ERROR;
	}

	sz = recv(s, buf, sizeof(buf), 0);
	if (sz == -1) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask test recv() failed");
		return NGX_ERROR;
	}

	close(s);

	out->buf = ngx_create_temp_buf(r->pool, sz);
	memcpy(out->buf->pos, buf, sz);
	out->buf->last += sz;
	out->next = NULL;
	out->buf->last_buf = 1;

	return NGX_OK;
}


#define MTASK_WAKE_TIMEDOUT 0x01
#define MTASK_WAKE_NOFINALIZE 0x02


/* The request pointer is read by intercepted functions.
   If non-NULL then control is yielded to caller context
   and callback IO event is scheduled for later activation.
   If NULL then usual behaivior takes place.
   */

/* NB: add __thread for multithreaded case */
static ngx_http_request_t *mtask_req;

#define mtask_current (mtask_req)

#define mtask_setcurrent(r) (mtask_req = (r))

#define mtask_resetcurrent() mtask_setcurrent(NULL)

#define mtask_scheduled (mtask_current != NULL)


static void mtask_start_scheduled() {
	
	ngx_http_mtask_loc_conf_t *mlcf;
	ngx_http_mtask_ctx_t *ctx;
	ngx_http_request_t *r = mtask_current;
	ngx_chain_t out;
	ngx_int_t res;

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, mtask_current->connection->log, 0, 
			"mtask start proc");

	mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mtask_module);

	if (mlcf->handler == NULL
			|| mlcf->handler(r, &out) != NGX_OK)
	{
		r->err_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
		out.buf = ngx_create_temp_buf(r->pool, 1);
		*out.buf->pos = '\n';
		out.buf->last++;
		out.next = NULL;
		out.buf->last_buf = 1;
	}

	mtask_resetcurrent();

	ngx_http_send_header(r);

	ngx_http_output_filter(r, &out);

	ctx = ngx_http_get_module_ctx(r, ngx_http_mtask_module);

	setcontext(&ctx->rctx);

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, mtask_current->connection->log, 0, 
			"mtask end proc");
}

static int mtask_wake(ngx_http_request_t *r, int flags) {

	ngx_http_mtask_ctx_t *ctx;

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask wake");

	ctx = ngx_http_get_module_ctx(r, ngx_http_mtask_module);

	mtask_setcurrent(r);

	if (flags & MTASK_WAKE_TIMEDOUT)
		ctx->timedout = 1;

	swapcontext(&ctx->rctx, &ctx->wctx);

	if (!mtask_scheduled) {

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask finalize");

		if (!(flags & MTASK_WAKE_NOFINALIZE))
			ngx_http_finalize_request(r, NGX_OK);

		return 1;
	}

	mtask_resetcurrent();

	return 0;
}

static void mtask_event_handler(ngx_event_t *ev) {

	ngx_http_request_t *r;
	ngx_connection_t *c;
	int wf = 0;

	c = ev->data;

	r = c->data;

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask event");

	if (ev->timedout)
		wf |= MTASK_WAKE_TIMEDOUT;

	mtask_wake(r, wf);
}

/* returns 1 on timeout */
static int mtask_yield(int fd, ngx_int_t event) {

	ngx_http_mtask_ctx_t *ctx;
	ngx_connection_t *c;
	ngx_event_t *e;
	ngx_http_mtask_loc_conf_t *mlcf;

	mlcf = ngx_http_get_module_loc_conf(mtask_current, ngx_http_mtask_module);

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, mtask_current->connection->log, 0, 
			"mtask yield '%V' (%s)", 
			&mtask_current->uri,
			event & NGX_WRITE_EVENT ? "write" : "read");

	ctx = ngx_http_get_module_ctx(mtask_current, ngx_http_mtask_module);

	c = ngx_get_connection(fd, mtask_current->connection->log);

	c->data = mtask_current;

	if (event == NGX_READ_EVENT)
		e = c->read;
	else
		e = c->write;

	e->data = c;
	e->handler = &mtask_event_handler;
	e->log = mtask_current->connection->log;

	ngx_add_event(e, event, 0);

	if (mlcf->timeout)
		ngx_add_timer(e, mlcf->timeout);

	ctx->timedout = 0;

	swapcontext(&ctx->wctx, &ctx->rctx);

	if (mlcf->timeout)
		ngx_del_timer(e);

	ngx_del_event(e, event, 0);

	ngx_free_connection(c);

	return ctx->timedout;
}

/* main request handler */
static ngx_int_t ngx_http_mtask_handler(ngx_http_request_t *r)
{
	ngx_http_mtask_loc_conf_t *mlcf;
	ngx_http_mtask_ctx_t *ctx;

	mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mtask_module);

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mtask_ctx_t));
	if (ctx == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;

	ngx_http_set_ctx(r, ctx, ngx_http_mtask_module);

	if (mlcf->handler == NULL)
		return NGX_ERROR;

	getcontext(&ctx->wctx);
	ctx->wctx.uc_stack.ss_sp = ngx_palloc(r->pool, mlcf->stack_size);
	ctx->wctx.uc_stack.ss_size = mlcf->stack_size;
	ctx->wctx.uc_stack.ss_flags = 0;
	ctx->wctx.uc_link = NULL;

	makecontext(&ctx->wctx, &mtask_start_scheduled, 0);

	r->main->count++;

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask init");

	if (mtask_wake(r, MTASK_WAKE_NOFINALIZE)) {

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask fast result");

		return NGX_OK;
	}

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
			"mtask detach");

	return NGX_DONE;
}

/* Syscalls interceptors */

typedef int (*accept_pt)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static accept_pt orig_accept;

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	ssize_t ret;
	int flags;

	if (mtask_scheduled) {

		flags = fcntl(sockfd, F_GETFL, 0);

		if (!(flags & O_NONBLOCK))
			fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	}
	
	for(;;) {

		ret = orig_accept(sockfd, addr, addrlen);
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		if (mtask_yield(sockfd, NGX_READ_EVENT)) {
			/* timeout */
			errno = EINVAL;
			return -1;
		}
	}
}


typedef int (*connect_pt)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static connect_pt orig_connect;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	ssize_t ret;
	int flags;
	socklen_t len;

	if (mtask_scheduled) {

		flags = fcntl(sockfd, F_GETFL, 0);

		if (!(flags & O_NONBLOCK))
			fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	}

	ret = orig_connect(sockfd, addr, addrlen);
	
	if (!mtask_scheduled || ret != -1 || errno != EINPROGRESS)
		return ret;

	for(;;) {

		if (mtask_yield(sockfd, NGX_WRITE_EVENT)) {
			errno = ETIMEDOUT;
			return -1;
		}

		len = sizeof(flags);

		flags = 0;

		ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &flags, &len);

		if (ret == -1 || !len)
			return -1;

		if (!flags)
			return 0;

		if (flags != EINPROGRESS) {
			errno = flags;
			return -1;
		}
	}
}


typedef ssize_t (*read_pt)(int fd, void *buf, size_t count);
static read_pt orig_read;

ssize_t read(int fd, void *buf, size_t count) {

	ssize_t ret;
	
	for(;;) {

		ret = orig_read(fd, buf, count);
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		if (mtask_yield(fd, NGX_READ_EVENT)) {
			errno = ECONNREFUSED;
			return -1;
		}
	}
}


typedef ssize_t (*write_pt)(int fd, const void *buf, size_t count);
static write_pt orig_write;

ssize_t write(int fd, const void *buf, size_t count) {

	ssize_t ret;

	for(;;) {

		ret = orig_write(fd, buf, count);
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		if (mtask_yield(fd, NGX_WRITE_EVENT)) {
			errno = ECONNRESET;
			return -1;
		}
	}
}


typedef ssize_t (*recv_pt)(int sockfd, void *buf, size_t len, int flags);
static recv_pt orig_recv;

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {

	ssize_t ret;

	for(;;) {

		ret = orig_recv(sockfd, buf, len, flags);
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		if (mtask_yield(sockfd, NGX_READ_EVENT)) {
			errno = ECONNRESET;
			return -1;
		}
	}
}


typedef ssize_t (*send_pt)(int sockfd, const void *buf, size_t len, int flags);
static send_pt orig_send;

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {

	ssize_t ret;
	
	for(;;) {

		ret = orig_send(sockfd, buf, len, flags);
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		if (mtask_yield(sockfd, NGX_WRITE_EVENT)) {
			errno = ECONNREFUSED;
			return -1;
		}
	}
}

/* TODO: handle poll/epoll/select */

__attribute__((constructor)) static void __init_scheduler() {

#define INIT_SYSCALL(name) orig_##name = (name##_pt)dlsym(RTLD_NEXT, #name)

	INIT_SYSCALL(accept);
	INIT_SYSCALL(connect);
	INIT_SYSCALL(read);
	INIT_SYSCALL(write);
	INIT_SYSCALL(recv);
	INIT_SYSCALL(send);

#undef INIT_SYSCALL

}

static void* ngx_http_mtask_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mtask_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mtask_loc_conf_t));

	conf->stack_size = NGX_CONF_UNSET_SIZE;

	conf->timeout = NGX_CONF_UNSET_MSEC;

	return conf;
}

static char* ngx_http_mtask_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mtask_loc_conf_t *prev = parent;
	ngx_http_mtask_loc_conf_t *conf = child;

	ngx_conf_merge_size_value(conf->stack_size,
			prev->stack_size,
			(size_t) MTASK_DEFAULT_STACK_SIZE);

	ngx_conf_merge_msec_value(conf->timeout,
			prev->timeout, 
			MTASK_DEFAULT_TIMEOUT);


	return NGX_CONF_OK;
}

static char * ngx_http_mtask(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mtask_loc_conf_t *mlcf = conf;
	ngx_http_core_loc_conf_t  *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	clcf->handler = ngx_http_mtask_handler;

	mlcf->handler = &test_mtask_handler;

	return NGX_CONF_OK;
}

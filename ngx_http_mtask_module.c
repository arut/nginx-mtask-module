/****************************************************************************
Copyright (c) 2011, Roman Arutyunyan (arut@qip.ru)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   
*****************************************************************************/

/*
 NGINX module providing userspace cooperative multitasking 
 for IO-bound content handlers
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ucontext.h>

/* TODO: this should be taken from 
   1) ulimit -s (default)
   2) settings in nginx.conf 
 */

#define MTASK_STACK_SIZE 1024

static char* ngx_http_mtask_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef void (*ngx_http_mtask_handler_pt)(ngx_http_request*);

struct ngx_http_mtask_loc_conf_s {

	ngx_http_mtask_handler_pt handler;
};

typedef struct ngx_http_mtask_loc_conf_s ngx_http_mtask_loc_conf_t;

struct ngx_http_mtask_ctx_s {

	/* current handler contexts: wake & return */
	ucontext_t wctx, rctx;

	/* this is not a real nginx connection
	   rather it's a fake object to make use of nginx event dispatcher 
	 */
	ngx_connection_t conn;

	void *stack;
};

typedef struct ngx_http_mtask_ctx_s ngx_http_mtask_ctx_t;

/* Module commands */

static ngx_command_t ngx_http_mtask_commands[] = {

	{	ngx_string("mtask"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF,
		ngx_http_mtask,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
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

void test_mtask_handler(ngx_http_request *r) {

	ngx_chain_t out;

	ngx_http_send_header(r);

	out.buf = ngx_create_temp_buf(r->pool, 6);
	memcpy(out.buf.pos, "preved", 6);
	out.next = NULL;
	out.buf->last_buf = 1;
	ngx_http_output_filter(r, &out);
}

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


static void mtask_start_scheduled(int pt) {

	ngx_http_mtask_handler_pt hnd = pt;	
	ngx_http_mtask_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_mtask_module);

	hnd(mtask_current);

	mtask_resetcurrent();

	setcontext(&ctx->rctx);
}

static void mtask_wake(ngx_http_request *r) {

	ngx_http_mtask_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_mtask_module);

	mtask_setcurrent(r);

	swapcontext(&ctx->rctx, &ctx->wctx);

	if (!mtask_scheduled) {

		munmap(ctx->stack, MTASK_STACK_SIZE);

		ngx_http_finalize_request(r, NGX_OK);
	}

	mtask_resetcurrent();
}

static void mtask_event_handler(ngx_event_t *ev) {

	ngx_http_request *r;
	ngx_connection_t *c;

	c = ev->data;

	r = c->data;

	ngx_epoll_del_event(ev, ev->event, 0);

	mtask_wake(r);
}

static void mtask_yield(int fd, ngx_int_t event) {

	ngx_http_mtask_ctx_t *ctx;
	ngx_event_t evt;

	ctx = ngx_http_get_module_ctx(mtask_current, ngx_http_mtask_module);

	memset(&evt, 0, sizeof(evt));

	ctx->conn.fd = fd;

	evt.data = &ctx->conn;
	evt.handler = &mtask_event_handler;

	/*TODO: set timeout*/
	ngx_add_event(&evt, event, 0);

	swapcontext(&ctx->wctx, &ctx->rctx);
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

	ctx->conn.data = r;
	ctx->conn.read = &mtask_event;
	ctx->conn.write = &mtask_event;

	ngx_http_set_ctx(r, ctx, ngx_http_mtask_module);

	if (mlcf->handler == NULL)
		return NGX_ERROR;

	ctx->stack = mmap(0, MTASK_STACK_SIZE, 
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	if (stack == MAP_FAILED)
		return NGX_ERROR;

	getcontext(&ctx->wctx);
	ctx->wctx.uc_stack.ss_sp = ctx->stack;
	ctx->wctx.uc_stack.ss_size = MTASK_STACK_SIZE;
	ctx->wctx.uc_stack.ss_flags = 0;
	ctx->wctx.uc_link = NULL;

	makecontext(&ctx->wctx, (void (*)())mtask_start_scheduled, 
			1, (int)mlcf->handler);

	r->main->count++;

	mtask_wake(r);

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

		mtask_yield(sockfd, NGX_READ_EVENT);
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

		mtask_yield(sockfd, NGX_WRITE_EVENT);

		len = sizeof(flags);

		flags = 0;

		ret = getsockopt(SOL_SOCKET, SO_ERROR, &flags, &len);

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

		mtask_yield(fd, NGX_READ_EVENT);
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

		mtask_yield(fd, NGX_WRITE_EVENT);
	}
}


typedef ssize_t (*recv_pt)(int sockfd, void *buf, size_t len, int flags);
static recv_pr orig_recv;

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {

	ssize_t ret;

	for(;;) {

		ret = orig_recv(sockfd, buf, len, flags);
	
		if (!mtask_scheduled || ret != -1 || errno != EAGAIN)
			return ret;

		mtask_yield(sockfd, NGX_READ_EVENT);
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

		mtask_yield(sockfd, NGX_WRITE_EVENT);
	}
}


__attribute__((constructor)) static void __init_scheduler() {

#define INIT_SYSCALL(name) orig_##name = (name##_pt*)dlsym(RTLD_NEXT, #name)

	INIT_SYSCALL(accept);
	INIT_SYSCALL(connect);
	INIT_SYSCALL(read);
	INIT_SYSCALL(write);
	INIT_SYSCALL(recv);
	INIT_SYSCALL(send);

#undef INIT_SYSCALL

}

/* TODO: handle poll/epoll/select */

static void* ngx_http_mtask_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mtask_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mtask_loc_conf_t));

	return conf;
}

static char* ngx_http_mtask_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
/*
	ngx_http_mtask_loc_conf_t *prev = parent;
	ngx_http_mtask_loc_conf_t *conf = child;
*/
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


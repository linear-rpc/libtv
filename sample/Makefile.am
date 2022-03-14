AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/deps/http-parser

LDADD = \
	$(top_srcdir)/src/.libs/libtv.a \
	$(LIBUV_DIR)/.libs/libuv.a -ldl

noinst_PROGRAMS = \
	tcp-server-sample \
	tcp-client-sample \
	ws-server-sample \
	ws-client-sample \
	timer-sample \
	pipe-server-sample \
	pipe-client-sample

if WITH_SSL
noinst_PROGRAMS += \
	ssl-server-sample \
	ssl-client-sample \
	wss-server-sample \
	wss-client-sample
endif

tcp_server_sample_SOURCES = \
    tcp-server-sample.c

tcp_client_sample_SOURCES = \
    tcp-client-sample.c

ws_server_sample_SOURCES = \
    ws-server-sample.c

ws_client_sample_SOURCES = \
    ws-client-sample.c

timer_sample_SOURCES = \
	timer-sample.c

if WITH_SSL
ssl_server_sample_SOURCES = \
    ssl-server-sample.c

ssl_client_sample_SOURCES = \
    ssl-client-sample.c

wss_server_sample_SOURCES = \
    wss-server-sample.c

wss_client_sample_SOURCES = \
    wss-client-sample.c

endif

pipe_server_sample_SOURCES = \
    pipe-server-sample.c

pipe_client_sample_SOURCES = \
    pipe-client-sample.c

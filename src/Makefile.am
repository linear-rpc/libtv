AM_CFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/include/websocket

nobase_include_HEADERS=$(top_srcdir)/include/*.h $(top_srcdir)/include/websocket/*.h

lib_LTLIBRARIES = \
	libtv.la

libtv_la_SOURCES = \
	buffer.c \
	handle.c \
	http_parser.c \
	loop.c \
	md5.c \
	pipe.c \
	stream.c \
	tcp.c \
	timer.c \
	ws.c \
	ws_frame.c \
	ws_handshake.c

if WITH_SSL
libtv_la_SOURCES += ssl.c
libtv_la_SOURCES += wss.c
else
libtv_la_SOURCES += sha1.c
endif

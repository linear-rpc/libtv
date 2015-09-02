SUBDIRS = . src

if WITH_SAMPLE
SUBDIRS += sample
endif

all-local:
	(cd deps/libuv; $(MAKE))

install-data-local:
	(cd deps/libuv; $(MAKE) install)

uninstall-local:
	(cd deps/libuv; $(MAKE) uninstall)

clean-local:
	(cd deps/libuv; $(MAKE) clean)

.PHONY: doc

doc:
	(cd doc; $(MAKE) doc)

if HAVE_PKG_CONFIG
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc
endif

SUBDIRS = . src

if WITH_SAMPLE
SUBDIRS += sample
endif

all-local:
	(cd deps/libuv; $(MAKE))
	@if [ $(WITH_TEST) ]; then \
		(cd deps/gmock-1.7.0; $(MAKE)); \
	fi

install-data-local:
	(cd deps/libuv; $(MAKE) install)

uninstall-local:
	(cd deps/libuv; $(MAKE) uninstall)

clean-local:
	(cd deps/libuv; $(MAKE) clean)
	@if [ $(WITH_TEST) ]; then \
		(cd deps/gmock-1.7.0; $(MAKE) clean); \
	fi
	@if [ $(WITH_SAMPLE) ]; then \
		(cd sample; $(MAKE) clean); \
	fi

.PHONY: doc

doc:
	(cd doc; $(MAKE) doc)

if HAVE_PKG_CONFIG
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc
endif

.PHONY: doc

all:	doc

doc:
	@if [ ! -z "${DOXYGEN}" ]; then \
		${DOXYGEN} Doxyfile; \
	fi

clean-local:
	rm -rf html

#!/bin/sh

aclocal -I . -I cf --force && \
	autoheader --force && \
	libtoolize --automake -c --force && \
	autoconf --force && \
	automake --add-missing --copy --force

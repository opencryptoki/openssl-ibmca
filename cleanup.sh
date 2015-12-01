#!/bin/sh

set -x
if [ -f Makefile ] ; then
        make -k clean
fi
rm -rf build-aux
rm -rf autom4te.cache
rm m4/* aclocal.m4
rm configure
rm config.*
rm libtool
find . -name Makefile -exec rm {} \;
find . -name Makefile.in -exec rm {} \;
find . -depth -name .deps -exec  rm -rf {} \;

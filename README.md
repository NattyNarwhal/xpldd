# `xpldd(1)`

A cross-platform `ldd` command. Unlike most `ldd` implementations in your
system's dynamic linker, this inspects dependencies and rpath entries in
them in an architecture agnostic way (via libelf), with additional flags
to make inspections of out-of-sysroot binaries easier.

Has only been tested on amd64 and ppc32 glibc binaries. Caveat emptor.

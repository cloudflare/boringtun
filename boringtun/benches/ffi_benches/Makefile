SRCDIR := $(dir $(lastword ${MAKEFILE_LIST}))
PKGDIR := $(realpath ${SRCDIR}/../..)
OBJDIR := $(shell pwd)
HOST_OS := $(shell uname)

ifeq (${HOST_OS},Darwin)
MACOSX_MAJOR_VERSION := $(shell sw_vers --productVersion | cut -d. -f1)
export MACOSX_DEPLOYMENT_TARGET=${MACOSX_MAJOR_VERSION}.0
endif

release/libboringtun.a: ${PKGDIR}/Cargo.toml
	cd ${PKGDIR} && cargo build --lib --release --target-dir ${OBJDIR} --features ffi-bindings
	@echo "$@: $$(cut -d: -f2- release/libboringtun.d)" > release/libboringtun-fixup.d

-include release/libboringtun-fixup.d

BENCH_CFLAGS := -I ${PKGDIR}/src
BENCH_SRCS := main.c wg_bench_client.c
BENCH_OBJS := $(patsubst %.c,%.o,${BENCH_SRCS})

# Build with profiling support
BENCH_CFLAGS += -g -fno-omit-frame-pointer
BENCH_LDFLAGS := -g -fno-omit-frame-pointer
release/libboringtun.a: export RUSTFLAGS=-C force-frame-pointers=y

%.o : %.c
	${CC} ${CFLAGS} ${BENCH_CFLAGS} -c -o $@ $<

ffi-bench: ${BENCH_OBJS} release/libboringtun.a
	${CC} ${LDLAGS} ${BENCH_LDFLAGS} -o $@ $^

clean:
	rm -f ${OBJDIR}/*.o
	rm -rf ${OBJDIR}/release
	rm -f ${OBJDIR}/ffi-bench

.PHONY: clean
.DEFAULT_GOAL := ffi-bench

ARG PLATFORM=amd64
FROM ${PLATFORM}/alpine:3.18 AS build

WORKDIR /build

RUN apk add --no-cache wget cmake make gcc g++ linux-headers openssl-libs-static openssl-dev \
            automake autoconf libevent-dev ncurses-dev msgpack-c-dev  \
            ncurses-libs ncurses-static ncurses-dev libevent-static msgpack-c  \
            libevent openssl zlib zlib-dev zlib-static

RUN set -ex; \
            mkdir -p /src/libssh/build; \
            cd /src; \
            wget -O libssh.tar.xz https://www.libssh.org/files/0.10/libssh-0.10.5.tar.xz; \
            tar -xf libssh.tar.xz -C /src/libssh --strip-components=1; \
            cd /src/libssh/build; \
            cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
            -DWITH_SFTP=OFF -DWITH_SERVER=OFF -DWITH_PCAP=OFF \
            -DBUILD_SHARED_LIBS=OFF -DWITH_GSSAPI=OFF ..; \
            make -j $(nproc); \
            make install

COPY compat ./compat
COPY *.c *.h autogen.sh Makefile.am configure.ac ./

RUN ./autogen.sh && ./configure --enable-static
RUN make -j $(nproc)
RUN objcopy --only-keep-debug tmate tmate.symbols && chmod -x tmate.symbols && strip tmate
RUN ./tmate -V

FROM alpine:3.18

RUN apk --no-cache add bash
RUN mkdir /build
ENV PATH=/build:$PATH
COPY --from=build /build/tmate.symbols /build
COPY --from=build /build/tmate /build

FROM debian:bullseye
WORKDIR /root/wine
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    pkg-config \
    flex \
    bison \
    fontforge \
    librsvg2-bin \
    imagemagick \
    icoutils \
    gettext \
    libgnutls28-dev \
    libgettextpo-dev \
    libxml-libxml-perl \
    libssl-dev \
    libusb-1.0.0-dev \
    gcc-mingw-w64-x86-64 \
    g++-mingw-w64-x86-64 mingw-w64-tools mingw-w64-x86-64-dev mingw-w64 mingw-w64-tools mingw-w64-common
COPY . .
RUN ./configure \
    --with-gnutls  \
    --without-hal \
    --without-oss  \
    --without-x \
    --without-freetype \
    --disable-tests  \
    --enable-win64 \
    --enable-maintainer-mode \
    CFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fno-stack-protector -Wformat -Werror=format-security -Wno-error -fcommon' \
    CPPFLAGS='-Wdate-time'  \
    CXXFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fno-stack-protector -Wformat -Werror=format-security' \
    FCFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fno-stack-protector'  \
    FFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fno-stack-protector'  \
    GCJFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fno-stack-protector'  \
    LDFLAGS='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,-rpath,/usr/lib/x86_64-linux-gnu/wine'  \
    OBJCFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -f-nostack-protector -Wformat -Werror=format-security'  \
    OBJCXXFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -f-nostack-protector -Wformat -Werror=format-security'

RUN make -j`nproc`
RUN make DESTDIR=build install

FROM debian:bullseye
COPY --from=0 /root/wine/build/ /
COPY --from=0 /usr/lib/gcc/x86_64-w64-mingw32 /usr/lib/gcc/x86_64-w64-mingw32
COPY --from=0 /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
COPY --from=0 /lib /lib
WORKDIR /root


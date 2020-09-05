FROM debian:10
WORKDIR /root/wine
RUN apt-get update && apt-get install -y \
    build-essential \
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
    g++-mingw-w64-x86-64
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
    CFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fstack-protector-strong -Wformat -Werror=format-security -Wno-error' \
    CPPFLAGS='-Wdate-time -D_FORTIFY_SOURCE=2'  \
    CXXFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fstack-protector-strong -Wformat -Werror=format-security' \
    FCFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fstack-protector-strong'  \
    FFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fstack-protector-strong'  \
    GCJFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fstack-protector-strong'  \
    LDFLAGS='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,-rpath,/usr/lib/x86_64-linux-gnu/wine'  \
    OBJCFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fstack-protector-strong -Wformat -Werror=format-security'  \
    OBJCXXFLAGS='-g -O2 -fdebug-prefix-map=/root/wine=. -fstack-protector-strong -Wformat -Werror=format-security'

RUN make -j`nproc`
RUN make DESTDIR=build install

FROM debian:10
COPY --from=0 /root/wine/build/ /
COPY --from=0 /usr/lib/gcc/x86_64-w64-mingw32/8.3-win32 /usr/lib/gcc/x86_64-w64-mingw32/8.3-win32
COPY --from=0 /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
COPY --from=0 /lib /lib
WORKDIR /root
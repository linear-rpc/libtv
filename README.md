# libtv

## Overview

libtv is a wrapper library of libuv to solve the problem
when embedding libuv into existing products, like multi-thread calling, transport, and so on.

## Feature highlights

 * Support multi-thread calling.
 * Support IPv6 dual stack.
 * Abstraction of TCP, SSL, WebSocket.

## Build Instructions

### Required tools and Dependencies

 * Python v2.6 or 2.7  
   Required if you want to build with gyp.
 * OpenSSL v1.0.1 or later  
   Required if you want to use {SSL, WSS} transport.
   If your operating system is Windows,
   download binary distributions from https://www.openssl.org/community/binaries.html and install it.

### Build with autotools

    $ ./bootstrap
    $ ./configure [--with-ssl=/path/to/OpenSSL]
    $ make clean all

### Build with gyp

#### Windows(Visual Studio)

    $ configure.py [-Dtarget_arch=[ia32,x64]] [-Denable_shared] [-Druntime_library=[md,mt]] [-Dwith_ssl=/path/to/OpenSSL]

Launch tv.sln or call msbuild like below

    $ msbuild tv.sln /p:Configuration=[Debug/Release]

#### xNix

    $ ./configure.py [-Denable_shared] [-Dwith_ssl=/path/to/OpenSSL]
    $ cd out
    $ make BUILDTYPE=[Debug/Release]

## License

The MIT License (MIT)  
See LICENSE for details.

And see some submodule LICENSEs(exist at deps dir).

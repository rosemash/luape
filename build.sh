#!/bin/bash -v
i686-w64-mingw32-gcc -Iinclude main.c -s lib/liblua5.1.a && python2 python/hack.py

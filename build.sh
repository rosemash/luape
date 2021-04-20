#!/bin/bash -v
i686-w64-mingw32-gcc -s -Ilua-5.1.5 lua-5.1.5/*.c main.c && python2 python/hack.py

#!/bin/bash -v
i686-w64-mingw32-gcc -s -Iinclude main.c include/*.c && python2 python/hack.py

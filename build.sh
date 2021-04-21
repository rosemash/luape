#!/bin/bash -v
i686-w64-mingw32-gcc -s -ffunction-sections -fdata-sections -Xlinker --gc-sections -Iinclude main.c include/*.c && python2 python/hack.py

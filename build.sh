#!/bin/bash
LUASOCKET_C="deps/luasocket/*.c -D LUASOCKET_C -lws2_32";
if [[ "$*" == "nosocket" ]]; then
	LUASOCKET_C="";
fi
mkdir -p bin
i686-w64-mingw32-gcc -v -ffunction-sections -fdata-sections -Xlinker --gc-sections -Os -s -Ideps/lua-5.1.5 -Ideps/luasocket main.c deps/lua-5.1.5/*.c $LUASOCKET_C && python2 python/hack.py

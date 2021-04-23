# Lua 5.1.5 and LuaSocket 3.0-rc1

Modifications have been made to the Lua implementation in this directory to expose certain function arguments to the generator script, which is used by `luape.exe` to generate new Lua runtime executables with custom options. Oiginal copyright for both projects is still intact. If you wish to use these libraries, you should get unmodified versions from their original sources. Swapping this Lua version with another will cause some features to stop working, for example the choice of whether to strip debug info when dumping bytecode for the output binary.

# Why include LuaSocket?

Socket I/O is an essential feature that Lua doesn't have by default. It allows IPC, network communication, HTTP (though no SSL), and polling/sleeping. It's very portable, and there are scripts that wouldn't be possible without it. If you want to compile luape without LuaSocket, you can: just edit `../main.c` to remove the code that adds LuaSocket's core bindings to package.path, and don't compile anything in `../deps/luasocket`. The included MinGW build script `../build.sh` will do this automatically if you run it as `./build.sh nosocket`.

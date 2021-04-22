# Lua 5.1.5 and LuaSocket 3.0-rc1

The versions of Lua 5.1.5 and LuaSocket 3.0-rc1 in this directory have been modified so that LuaSocket's `socket.core` and `mime.core` are included as built-in Lua modules. Original copyright for both projects is still intact. If you want to use these libraries, you should get unmodified versions from their original source.

# Why include LuaSocket?

Socket I/O is an essential feature that Lua doesn't have by default. It allows IPC, network communication, HTTP (though no SSL), and polling/sleeping. It's very portable, and there are scripts that wouldn't be possible without it. If you want to compile luape without LuaSocket, you can: just edit `/main.c` to remove the code that adds LuaSocket's core bindings to package.path, and don't compile anything in `/deps/luasocket`. The included MinGW build script `/build.sh` will do this automatically if you run it as `./build.sh nosocket`.

# luape
A simple Windows executable that frankensteins with Lua to create portable scripts.

# How does it work?

You will have 2 files: `fuser.exe` and `luastub.bin`. `luastub.bin` is a simple Windows executable with the Lua runtime statically linked to it. It looks for a string in memory and tries to execute it as a Lua script. Said string actually resides in a PE section called .lua, which is empty and has a size of 0 unless the stub is modified. That modification is done by `fuser.exe`, which takes 3 arguments: the stub file, a Lua script, and the output filename. The fuser will make a copy of `luastub.bin` with the Lua script embedded, which should then be able to run without external dependencies. In fact, `fuser.exe` itself is nothing more than a Lua script appended to the stub.

# How do I use it?

You can build it (not recommended) or download it from [here](https://github.com/rosemash/luape/releases/download/1.0.0/luape.zip). The zip contains both files precompiled.

Usage: `fuser.exe <luastub.bin> <source OR file:source.lua> <output.exe>`

For example, if you have a file called hello.lua in the same directory as the fuser and stub that you wish to fuse into hello.exe: `fuser.exe luastub.bin file:hello.lua hello.exe`.

# Does it work with compiled Lua bytecode?

In my tests, it complained about a bad Lua header. I couldn't figure out why. My best guess is a version mismatch, but both the library and the Lua version on my system are Lua 5.1.5. If you want to try it, you'll have to modify the fuser script to write the size of the chunk to the .lua section, then read it in main.c so it can be passed to luaL_loadbuffer.

# Why not LuaJIT?

I already had Lua 5.1.5 working on my system. I didn't get LuaJIT for 2 reasons: I didn't think this project would be finished, and I'm stupid and struggle with linkers. It should be easy to replace.

# How do I build it?

This is tricky, because the method of building involves doing a lot of things to the compiled executable, and it may break with other configurations.

I have only tested compilation on Debian Buster using MinGW. To follow in my footsteps, make sure you've installed `python2` and `mingw-w64`. I'm pretty sure all other dependencies are included in the project.

When you're ready, run `./build.sh` in the project root.

If you are on a different system or using a different compiler with a different configuration, **MAKE SURE TO STRIP DEBUG SYMBOLS!** That's what the `-s` flag is doing in `build.sh`. The hack we're doing expects the PE sections to be at the very end of the file. If you can somehow include symbols without spamming useless garbage to the end of the file, go ahead, but I recommend generating the simplest PE you can with your compiler settings, otherwise it's going to break.

If you're compiling with your own configuration, make sure the output is `a.exe` in the project root folder. It will crash if you run it. Run `python2 python/hack.py` to do the hack. It uses a PE section editing module called SectionDoubleP (it appears to be abandoned by its creator n0p, but it's invaluable) and should populate `bin` with `fuser.exe` and `luastub.bin`, which both derive from `a.exe`.

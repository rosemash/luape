# luape
A simple Windows executable that frankensteins with Lua to create portable scripts.

# How does it work?

You will have 2 files: `fuser.exe` and `luastub.bin`. `luastub.bin` is a simple Windows executable with the Lua runtime statically linked into it. It looks for Lua bytecode in memory and tries to run it. Said bytecode actually resides in a PE section called .lua, which is empty and has a size of 0 by default. The bytecode is patched into the .lua section by `fuser.exe`, which takes 3 arguments: the stub file, a Lua script, and the output filename. The fuser will compile the script, then make a copy of `luastub.bin` with the bytecode embedded, which can run without external dependencies. In fact, `fuser.exe` itself is nothing more than a Lua script merged with the stub.

# How do I use it?

You can build it (not recommended) or download it from [here](https://github.com/rosemash/luape/releases/download/1.1.1/luape.zip). The zip contains both files precompiled.

Usage: `fuser.exe <luastub.bin> <source OR file:source.lua> <output.exe>`

For example, if you have a file called hello.lua in the same directory as the fuser and stub that you wish to compile into hello.exe: `fuser.exe luastub.bin file:hello.lua hello.exe`.

# How do I build it?

This is tricky, because the method of building involves doing a lot of things to the compiled executable, and it may break with other configurations.

I have only tested compilation on Debian Buster using MinGW. To follow in my footsteps, make sure you've installed `python2`, `mingw-w64`, and `wine32`. I'm pretty sure all other dependencies are included in the project.

When you're ready, run `./build.sh` in the project root.

If you are on a different system or using a different compiler with a different configuration, **MAKE SURE TO STRIP DEBUG SYMBOLS!** That's what the `-s` flag is doing in `build.sh`. The hack we're doing expects the PE sections to be at the very end of the file. If you can somehow include symbols without spamming useless garbage to the end of the file, go ahead, but I recommend generating the simplest PE you can with your compiler settings, otherwise it's going to break.

If you're compiling with your own configuration, make sure the output is `a.exe` in the project root folder. It will crash if you run it. Run `python2 python/hack.py` to do the hack. It uses a PE section editing module called SectionDoubleP (it appears to be abandoned by its creator n0p, but it's invaluable) and should populate `bin` with `fuser.exe` and `luastub.bin`, which both derive from `a.exe`.

# Why?

I've always wanted something like this, but never found something that met my needs. My wishes were:

- To distribute simple standalone Lua scripts to anyone

- To require no dependencies on the end user's PC (everything self-contained)

- To require no dependencies or complicated steps on the system packaging the script

While I came across projects that met some of these requirements (mostly the 1st and 2nd), nothing was completely satisfying. So one night I stayed up all night and hacked this together.

# Can I use it in my project?

[Yes.](https://github.com/rosemash/luape/blob/master/LICENSE) Just don't be upset if it breaks.


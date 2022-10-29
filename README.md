# luape

A simple Windows executable that frankensteins with Lua to create portable scripts.

# How does it work?

The output of this source code is `luape.exe`, a simple Windows executable containg 3 things: the Lua runtime, an entry function that looks for Lua code in memory and tries to run it, and a script in that memory location. The script contained there by default is designed to replace itself with any arbitrary Lua code, producing a new standalone executable.

The LuaSocket version of luape is compatible with Windows Vista and higher, and has access to low-level LuaSocket bindings (`socket.core` and `mime.core`). Check out the .lua files in `/deps/luasocket` to see how the official LuaSocket library scripts implement those bindings, and copy what you need into your own code for use with luape.

# How do I use it?

You can build it (not recommended) or download one of the prebuilt versions [here](https://github.com/rosemash/luape/releases/latest).

Usage: `luape.exe <source OR file:source.lua> <output.exe> [option...]`

Simple example: `luape.exe "print('hello world')" hello.exe`

Here are the available options:

* `/name=...` Set the Lua chunk name to an alphanumeric string (example: `/name=happychunk`)

* `/debug` - Include Lua debug information in the compiled chunk

* `/hidden` - Generate a PE that doesn't have a console window or GUI

Let's say you have a file called `hello.lua` in the same directory as `luape.exe` that you wish to compile into `hello.exe`, with debug information intact and the chunkname set to "myscript". This is the command you would execute: `luape.exe file:hello.lua hello.exe /debug /name=myscript`.

Options must go after the first and second argument. If the first argument doesn't begin with `file:` it will be interpreted as the source code, otherwise it will open from the filename after the separator and read that.

# How do I build it?

This is tricky, because the method of building involves doing unspeakable things to the compiled executable, and it might break when attempting to compile from other configurations. I have only tested compilation on Debian Buster using MinGW. To follow in my footsteps, make sure you've installed `mingw-w64`, `wine32`, and `python2` with the `future` module (`sudo apt install python-pip && sudo pip install future`), then keep reading.

If your package manager can't find wine32 and you're on Debian, it's because you have to enable 32-bit packages: run `sudo dpkg --add-architecture i386`, `sudo apt update`, then try again.

You will need to update `_WIN32_WINNT` in `/usr/i686-w64-mingw32/include/_mingw.h` to a value of `0x0600` (Windows Vista and higher) to compile with LuaSocket, otherwise you won't have a definition for the function `inet_pton`, which is necessary for ipv6 support. There unfortunately doesn't seem to be a way to override it without changing that file.

When you're ready, run `./build.sh` in the project root. If you want to compile without LuaSocket, run `./build.sh nosocket` instead.

If you are on a different system or using a different compiler with a different configuration, **MAKE SURE TO STRIP DEBUG SYMBOLS!** That's what the `-s` flag is doing in `build.sh`. The hack we're doing expects the PE sections to be at the very end of the file. If you can somehow include symbols without spamming useless garbage to the end of the file, go ahead, but I recommend generating the simplest PE you can with your compiler settings, otherwise it's going to break.

If you're compiling with your own configuration, make sure the output is `a.exe` in the project root folder. It will crash if you run it. Run `python2 python/hack.py` to do the hack. It uses a PE section editing module called SectionDoubleP (it appears to be abandoned by its creator n0p, but it's invaluable) and should populate `bin` with `luape.exe`, which is a patched version of `a.exe` fused with a specialized version of `lua/generator.template.lua` generated during the build. The script will then run `luape.exe` on its own Lua source, creating a bootstrapped version of `luape.exe` compiled with whatever Lua version it's running.

After a successful build, the resulting executable should have the same behavior as the one currently available on the releases page. It is recommended to test all flags to make sure.

# Why?

I've always wanted something like this, but never found something that met my needs. My wishes were:

- To distribute simple standalone Lua scripts to anyone

- To require no external dependencies on the end user's PC (everything self-contained)

- To require no external dependencies or complicated steps on the system packaging the script

While I came across projects that met some of these requirements (mostly the 1st and 2nd), nothing was completely satisfying. So one night I stayed up all night and hacked this together.

# Can I use it in my project?

[Yes.](https://github.com/rosemash/luape/blob/master/LICENSE) Just don't be upset if it breaks.

 

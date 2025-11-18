# this is the post-build script that modifies the binary compiled from main.c to point to the Lua script
# what's happening here is very hacky, I don't expect it to build correctly on all systems
# credit for the included libraries goes to their respective authors
# SectionDoubleP: https://git.n0p.cc/SectionDoubleP.git/
#
# when this script is called from the root of the project, it:
# * patches in a new PE section called .lua, for lua bytcode to live in
# * updates the magic offset (0x13371337) to point to the .lua section
# * copies the lua generator script template and tells it about all the necessary offsets
# * creates a temporary version of the binary called bin/luape.exe with the modified template script embedded
# * uses that version of the binary to bootstrap a final compiled version of itself
# * overwrites the temporary binary with the final bootstrapped binary

import os
import sys
import struct
import subprocess
from deps import pefile
from deps import SectionDoubleP as sdp

# open the file in pefile and SectionDoubleP so we can edit sections
pe = pefile.PE("a.exe")
sections = sdp.SectionDoubleP(pe)

# this function adds the .lua section for scripts to live in
# characteristics (from objdump -h on the final executable): CONTENTS, ALLOC, LOAD, READONLY, DATA
def addLuaSection(data):
	return sections.push_back(Characteristics=0x40000040, Name=".lua", Data=data)

# add an empty lua section so we can look at it and determine the needed offsets
pe = addLuaSection("")

# update the magic offset constant (0x13371337) in our compiled template PE to point to the new section, using a string replace
luaSectionStart = pe.sections[-1].VirtualAddress
pe.__data__ = pe.__data__.replace("\x37\x13\x37\x13", struct.pack("I", luaSectionStart))

# open the generator script for appending to the binary
with open("lua/generator.lua.template", "r") as f:
	fusesource = f.read()

# creating a specialized version of the generator script that contains the correct offsets for this specific build of the binary
fusesource = fusesource.format(
	isizeoffs = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
	smodeoffs = pe.OPTIONAL_HEADER.get_field_absolute_offset("Subsystem"),
	vsizeoffs = pe.sections[-1].get_field_absolute_offset("Misc_VirtualSize"),
	rsizeoffs = pe.sections[-1].get_field_absolute_offset("SizeOfRawData"),
	imagesize = pe.OPTIONAL_HEADER.SizeOfImage,
	luastart = pe.sections[-1].PointerToRawData,
	alignment = pe.OPTIONAL_HEADER.FileAlignment	# the generator adds bytes to the end of the file to compensate for file alignment, so we supply the alignment here
)

# removing the empty lua section and replacing it with one that contains the generator script
sections.pop_back()
pe = addLuaSection(struct.pack("I", len(bytes(fusesource))) + fusesource)

# writing the first version of the generator executable
pe.write(filename="bin/luape.exe")

# the generator executable re-creates itself, using itself (bootstrap step that doesn't involve SectionDoubleP, acts as a sanity check)
print("attempting to perform a pro gamer move")
command = ["bin/luape.exe", fusesource, "bin/luape_bootstrapped.exe", "/debug", "/name=luape"]
if sys.platform != "win32":
	command.insert(0, "wine")
subprocess.call(command)

# replace the SectionDoubleP-generated generator with the bootstrapped one
os.rename("bin/luape_bootstrapped.exe", "bin/luape.exe")
print("overwrote bin/luape.exe with bin/luape_bootstrapped.exe")

# delete a.exe (initial executable before modifications, now garbage)
os.remove("a.exe")
print("cleaned up debris")

print("done")

# disclaimer: this is a hack that I did for fun, there is no guarantee this will work on all systems
# I've wanted something like this for a while and never found an equivalent
# credit for the included libraries goes to their respective authors
# (although I cannot find the original copy of SectionDoubleP)
# matrix contact: @autumn:raincloud.dev

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

# update the magic offset constant (0x13371337) in our compiled template PE to point to the new section, using... a string replace!!!
luaSectionStart = pe.sections[-1].VirtualAddress
pe.__data__ = pe.__data__.replace("\x37\x13\x37\x13", struct.pack("I", luaSectionStart))

# for reasons of poetry, the generator will itself be a lua script appended to the binary, and soon it's going to compile itself
with open("lua/generator.lua.template", "r") as f:
	fusesource = f.read()

# specializing the script for this build by giving the needed numbers to generator script template (in the order they appear in the file)
fusesource = fusesource.format(
	o1 = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
	o2 = pe.sections[-1].get_field_absolute_offset("Misc_VirtualSize"),
	o3 = pe.sections[-1].get_field_absolute_offset("SizeOfRawData"),
	imagesize = pe.OPTIONAL_HEADER.SizeOfImage,
	luastart = pe.sections[-1].PointerToRawData,
	alignment = pe.OPTIONAL_HEADER.FileAlignment	# the generator adds bytes to the end of the file to compensate for file alignment, so we supply the alignment here
)

# removing the empty lua section and replacing it with one that contains the generator script
sections.pop_back()
pe = addLuaSection(struct.pack("I", len(bytes(fusesource))) + fusesource)

# writing the initial generator program
pe.write(filename="bin/luape.exe")

# now the moment of truth: to complete the universe, the generator executable is about to re-create itself, using itself, with no help from SectionDoubleP
print("attempting to perform a pro gamer move")
command = ["bin/luape.exe", fusesource, "bin/luape_bootstrapped.exe"]
if sys.platform != "win32":
	command.insert(0, "wine")
subprocess.call(command)

# replace the SectionDoubleP-generated generator with the bootstrapped one
os.rename("bin/luape_bootstrapped.exe", "bin/luape.exe")
print("overwrote bin/luape.exe with bin/luape_bootstrapped.exe")

# delete a.exe because it's stupid and useless
os.remove("a.exe")
print("cleaned up debris")

print("done")

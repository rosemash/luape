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
pe = pefile.PE('a.exe')
sections = sdp.SectionDoubleP(pe)

# this function adds the .lua section for scripts to live in
# characteristics (from objdump -h on the final executable): CONTENTS, ALLOC, LOAD, READONLY, DATA
def addLuaSection(data):
	return sections.push_back(Characteristics=0x40000040, Name='.lua', Data = data)

# add an empty lua section so we can look at it and determine the offsets in the file for the fuser
pe = addLuaSection("")

# update the magic offset constant (0x13371337) in our compiled template PE to point to the new section, using... a string replace!!!
luaSectionStart = pe.sections[-1].VirtualAddress
pe.__data__ = pe.__data__.replace("\x37\x13\x37\x13", struct.pack("I", luaSectionStart))

# write our current edit of the PE to a file, the fuser will use it as the base for future executables
pe.write(filename="bin/luastub.bin")

# for reasons of poetry, our exe/lua fuser will, itself, be a fused lua executable running a generated version of our fuser script
with open('lua/fuser.lua.template', 'r') as f:
	fusesource = f.read()

# the fuser script script seeks through the file linearly, adjusting 4-byte integers on its way to accomodate the size of the user-supplied script
# to know what places to stop, it uses a relative offset from the last area edited (plus 4 bytes) so it doesn't have to re-calculate as it seeks
# the only benefit of doing this is simplicity on the lua side, it's just how it was written, and we're generating the offsets anyway so it doesn't matter
# I'm supplying the offsets to the fuser in this script, which is why we need the function below
seeker = 0
def seek(offset):
	global seeker
	result = offset - seeker
	seeker = offset + 4
	return result

# giving the needed offsets to lua fuser template :yum:
fusesource = fusesource.format(
	o1 = seek(pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage")),
	o2 = seek(pe.sections[-1].get_field_absolute_offset("Misc_VirtualSize")),
	o3 = seek(pe.sections[-1].get_field_absolute_offset("SizeOfRawData")),
	alignment = pe.OPTIONAL_HEADER.FileAlignment	# the fuser adds bytes to the end of the file to compensate for file alignment, so we supply the alignment here
)

# removing the empty lua section and replacing it with one that contains the fuser script
sections.pop_back()
pe = addLuaSection(struct.pack("I", len(bytes(fusesource))) + fusesource)

# writing the initial fuser
pe.write(filename='bin/fuser.exe')

# now the moment of truth: to complete the universe, the fuser executable is about to re-create itself, using itself, with no help from SectionDoubleP
print("attempting to perform a pro gamer move")
command = ["bin/fuser.exe", "bin/luastub.bin", fusesource, "bin/fuser_bootstrapped.exe"]
if sys.platform != "win32":
	command.insert(0, "wine")
subprocess.call(command)

# replace the SectionDoubleP-generated fuser with the bootstrapped one
os.rename("bin/fuser_bootstrapped.exe", "bin/fuser.exe")
print("overwrote bin/fuser.exe with bin/fuser_bootstrapped.exe")

# delete a.exe because it's stupid and useless
os.remove("a.exe")
print("cleaned up debris")

print("done")

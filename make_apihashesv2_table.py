#!/usr/bin/python3
# © 2022 AO Kaspersky Lab. All Rights Reserved.
#
# Generate a table of pre-calculated API hashes for the IDA plugin

import pefile, sys, struct, zlib
import os, os.path

# Helper routines for rotation
def Ror32(val, howmuch):
    howmuch = howmuch % 32
    return ((val >> howmuch) | ( val<< (32-howmuch) )) & 0xFFFFFFFF

def Rol32(val, howmuch):
    howmuch = howmuch % 32
    return ((val << howmuch) | ( val>> (32-howmuch) )) & 0xFFFFFFFF

# Metasploit-style ROR 0xD hash (library name + api name)
def Ror0D(name, libname):
    libhash = 0
    for c in libname:
        c = c - 0x20 if c >= 0x61 else c
        libhash = Ror32(libhash, 0xD)
        libhash += c
        libhash = Ror32(libhash, 0xD)
        # next one is zero

    libhash = Ror32(libhash, 0xD)
    libhash = Ror32(libhash, 0xD)

    res = 0
    for c in name:
        c = ord(c)
        res = Ror32(res, 0xD)
        res += c
    res = Ror32(res, 0xD)

    return (res + libhash) & 0xFFFFFFFF

def ShadowHammer(name, libname):
    res = 0
    for c in name:
        c = ord(c)
        res = res * 0x83
        res += c

    return res & 0x7FFFFFFF

# Raw ROR 0xD
def Ror0D_Simple(name, libname):
    res = 0
    for c in name:
        c = ord(c)
        res = Ror32(res, 0xD)
        res += c
    return res & 0xFFFFFFFF

def Djb2(name, libname):
    res = 0x1505
    for c in name:
        c = ord(c)
        res *= 0x21
        res += c

    return res & 0xFFFFFFFF

def Adler32_DarkSide(name, libname):
    return zlib.adler32(name.encode('utf-8'), 0xFFFFFFFF) & 0xFFFFFFFF

def Crc32(name, libname):
    return zlib.crc32(name.encode('utf-8')) & 0xFFFFFFFF

# All hashing routines
hashers = [Ror0D, ShadowHammer, Djb2, Adler32_DarkSide, Crc32, Ror0D_Simple]
# hash:name dict
hashtable = {}
# unique name set for exported symbols
allStrings = set()

files_to_process = []

if len(sys.argv) < 2:
    print("Make the apihashesv2 binary database, for the IDA plugin")
    print("Usage: [dir with DLLs] [filename.dll] ...")
    exit()

for f in sys.argv[1:]:
    if os.path.isfile(f):
        files_to_process.append(f)
    elif os.path.isdir(f):
        for dirname, _, filenames in os.walk(f):
            for fname in filenames:
                files_to_process.append(os.path.join(dirname, fname))

print(f"Processing {len(files_to_process)} files...")

for f in files_to_process:
    try:
        pe = pefile.PE(f)
    except:
        print(f"Unable to load {f} as a PE file, skipping...")
        continue

    try:
        libname = pe.DIRECTORY_ENTRY_EXPORT.name
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                name = exp.name.decode('utf-8')
                for hasher in hashers:
                    hashvalue = hasher(name, libname)
                    hashtable[hashvalue] = name
                    allStrings.add(name)
                    # Debug point - you can print out the results of hashing
                    print(f'{hex(hashvalue)} : {name}')
            except:
                pass
    except:
        pass

# No names at all? Nothing to do here
if len(hashtable) == 0:
    exit()

# Now build a binary database
# QWORD                         number of items
# [2*QWORD]*number of items     pairs of [hash,name offset], sorted by the hash value
# rest of the file              null-terminated symbol names
stringLocations = {}

headerSize = 8 +  16 * len(hashtable)

stringbuf = b""
for string in sorted(allStrings):
    pos = len(stringbuf) + headerSize
    stringLocations[string] = pos
    stringbuf += string.encode('utf-8') + b'\x00'
stringbuf += b'\x00' # Empty string as an ending mark

output = b""
# Number of items 
output += struct.pack("<Q", len(hashtable))

# Pairs of [hash, name offset]
for hashvalue in sorted(hashtable.keys()):
    # We write a pair of a hash and a name position
    output += struct.pack("<Q", hashvalue)
    output += struct.pack("<Q", stringLocations[hashtable[hashvalue]])

# All the symbol names
output += stringbuf # All the strings, sorted

# Sorted strings compress nicely, to decrease load time - I/O is slower
output = zlib.compress(output)

fname = "apihashesv2.bin"
with open(fname, "w+b") as f:
    f.write(output)

print("Written the hashes file to " + fname + ", enjoy!")


# © 2022 AO Kaspersky Lab. All Rights Reserved.

from ctypes import *
import zlib, bisect, struct

# Array of the [hash, name offset] pairs
tokens = None
# The whole decompressed database
decomp = None

class HashRecBin(Structure):
    _fields_ = [ ('hash', c_uint64), ('off', c_uint64 ) ]

    def __lt__(self,other):
        return self.hash < other

def LoadHashes(fileName):
    global tokens, decomp

    with open(fileName, "rb") as f:
        b = bytes(f.read())
        decomp = zlib.decompress(b)
        # Read the header
        numItems = struct.unpack("<Q", decomp[0:8])[0]
        # Read all the hash values
        tokensArr = HashRecBin * numItems
        tokens = tokensArr.from_buffer_copy(decomp[8:8+numItems*sizeof(HashRecBin)])

    return numItems

def FindHash(value):
    i = bisect.bisect_left(tokens, value)
    if i >= len(tokens):
        return None
    if tokens[i].hash != value:
        return None
    fname = ""
    for c in decomp[tokens[i].off:]:
        if c == 0:
            break
        fname = fname + chr(c)
    return fname

def main():
    print('Apihashes v2 test')
    LoadHashes("apihashesv2.bin")
    print(f'Hashes loaded, {len(tokens)} items')
    if FindHash(0x726774c) != 'LoadLibraryA':
        raise RuntimeError('Cannot find the hash for LoadLibraryA')
    if FindHash(0x6F721347) != 'RtlExitUserThread':
        raise RuntimeError('Cannot find the hash for RtlExitUserThread')
    if FindHash(0x6174A599) != 'connect':
        raise RuntimeError('Cannot find the hash for connect')
    print('All good.')

if __name__ == "__main__":
    main()

#!/usr/bin/python3

import sys

offending_code = bytes.fromhex("10 30 9F E5  7C 00 93 E5  20 03 A0 E1  01 00 20 E2  01 00 00 E2  1E FF 2F E1")
benign_code = bytes.fromhex("01 00 A0 E3  01 00 A0 E3  01 00 A0 E3  01 00 A0 E3  01 00 A0 E3  1E FF 2F E1")

with open(sys.argv[1], "r+b") as fp:
    data = bytearray(fp.read())
    offset = data.index(offending_code)
    data[offset:offset+len(offending_code)] = benign_code
    if len(sys.argv) > 2:
        with open(sys.argv[2], "wb") as ofp:
            ofp.write(data)
    else:
        fp.seek(0)
        fp.write(data)

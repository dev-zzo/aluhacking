#!/usr/bin/env python3

# structures mumbo-jumbo

import struct

class BetterStructMeta(type):
    def __new__(cls, clsname, superclasses, attributedict):
        if clsname != 'BetterStruct':
            fields = attributedict['__fields__']
            field_types = [ _[0] for _ in fields ]
            field_names = [ _[1] for _ in fields if _[1] is not None ]
            attributedict['__names__'] = field_names
            s = struct.Struct(attributedict.get('__endian__', '') + ''.join(field_types))
            attributedict['__struct__'] = s
            attributedict['size'] = s.size
        return type.__new__(cls, clsname, superclasses, attributedict)

class BetterStruct(metaclass=BetterStructMeta):
    def __init__(self):
        for t, n in self.__fields__:
            if 's' in t:
                setattr(self, n, b'')
            elif t in ('Q', 'I', 'H', 'B'):
                setattr(self, n, 0)

    @classmethod
    def unpack_from(cls, buffer, offset=0):
        fields = cls.__struct__.unpack_from(buffer, offset)
        instance = cls()
        for n, v in zip(cls.__names__, fields):
            setattr(instance, n, v)
        return instance

    def pack(self):
        return self.__struct__.pack(*[ getattr(self, n) for n in self.__names__ ])

    def __str__(self):
        return '(' + ', '.join([ "'%s': %s" % (n, repr(getattr(self, n))) for n in self.__names__ if n is not None ]) + ')'

# MOD structures defined

MODHDR_MAGIC = 0xCCDDEE55

class ModHeader(BetterStruct):
    __endian__ = '<'
    __fields__ = [
        ('I', 'crc'),
        ('I', 'magic'),
        ('I', 'info_version'),
        ('I', 'hdr_len'),
        ('I', 'body_len'),
        ('16s', 'version'),
    ]

# States
MODHDR_INVALID = 0x00000000
MODHDR_PENDING = 0xefffffff
MODHDR_ACTIVE  = 0xefefefff
MODHDR_RETIRED = 0xefefefef

class BodyHeader(BetterStruct):
    __endian__ = '<'
    __fields__ = [
        ('I', 'state'),
        ('I', 'tries'),
        ('I', 'magic'),
    ]

HUNK_COUNT = 8

# Types
HUNK_EMPTY =           0
HUNK_UBOOT_UIMAGE =    1
HUNK_KERNEL_UIMAGE =   2
HUNK_FS_SQUASHFS =     3
HUNK_PRIVATE =         4
HUNK_SIGNATURE =       5

_hunk_type_str = [
    "EMPTY",
    "UBOOT",
    "KERNEL",
    "SQUASHFS",
    "PRVATE",
    "SIGNATURE"
]

# Flags
HUNK_IGNORE =       (1 << 0)
HUNK_CHECK_CRC =    (1 << 1)
HUNK_SHA256 =       (1 << 2)
HUNK_RSA_PKCS1 =    (1 << 3)

class HunkHeader(BetterStruct):
    __endian__ = '<'
    __fields__ = [
        ('I', 'type'),
        ('16s', 'version'),
        ('I', 'flags'),
        ('I', 'offset'),
        ('I', 'length'),
        ('I', 'crc'),
    ]

# Let the fight begin

import os
from binascii import crc32
from hashlib import sha256
import sys
import argparse

def info(mod_fp):
    header = ModHeader.unpack_from(mod_fp.read(ModHeader.size))
    mod_fp.seek(0)
    signed_header = mod_fp.read(header.hdr_len)
    crc = crc32(bytes.fromhex('00000000') + signed_header[4:], 0) & 0xFFFFFFFF
    print("header CRC: %08X, computed crc: %08X" % (header.crc, crc))
    header_digest = sha256(signed_header).digest()
    print("header digest: %s" % (header_digest.hex(),))
    print("MOD version: %s" % (header.version.decode()))

    mod_fp.seek(ModHeader.size)
    hunks = []
    print("     Type    Flags    Offset   Length     CRC32 Version string")
    for i in range(HUNK_COUNT):
        hunk = HunkHeader.unpack_from(mod_fp.read(HunkHeader.size))
        print("%9s %08X  %08X %08X  %08X %16s" % (_hunk_type_str[hunk.type], hunk.flags, hunk.offset, hunk.length, hunk.crc, hunk.version.decode()))
        hunks.append(hunk)

def extract(mod_fp):
    header = ModHeader.unpack_from(mod_fp.read(ModHeader.size))
    hunks = []
    print("      Type    Flags    Offset   Length     CRC32 Version string")
    for i in range(HUNK_COUNT):
        hunk = HunkHeader.unpack_from(mod_fp.read(HunkHeader.size))
        print("%10s %08X  %08X %08X  %08X %16s" % (_hunk_type_str[hunk.type], hunk.flags, hunk.offset, hunk.length, hunk.crc, hunk.version.decode()))
        hunks.append(hunk)

    digests = []
    for i in range(HUNK_COUNT):
        digest = mod_fp.read(64).decode().rstrip('\0')
        mod_fp.read(1)
        digests.append(bytes.fromhex(digest))
        #if digest:
        #    print(digest)

    for i in range(HUNK_COUNT):
        hunk = hunks[i]
        if hunk.type == HUNK_UBOOT_UIMAGE:
            ext = "uboot.uImage"
        elif hunk.type == HUNK_KERNEL_UIMAGE:
            ext = "kernel.uImage"
        elif hunk.type == HUNK_FS_SQUASHFS:
            ext = "squashfs"
        elif hunk.type == HUNK_PRIVATE:
            ext = "bin"
        else:
            continue
        mod_fp.seek(hunk.offset)
        data = mod_fp.read(hunk.length)
        if hunk.flags & HUNK_CHECK_CRC:
            pass
        if hunk.flags & HUNK_SHA256:
            digest = sha256(data).digest()
            if digest != digests[i]:
                print("  SHA256 mismatch for hunk %d! expected %s, computed %s" % (i, digests[i].hex(), digest.hex()))
        with open("%s_%s.%s" % (header.version.decode().rstrip('\0'), hunk.version.decode().rstrip('\0'), ext), "wb") as ofp:
            ofp.write(data)

def build(mod_fp, version, state, hunks, signkey=None):
    header = ModHeader()
    header.magic = MODHDR_MAGIC
    header.info_version = 2
    header.version = version.encode()
    header.hdr_len = header.size + HunkHeader.size * HUNK_COUNT + (64+1) * HUNK_COUNT
    header.body_len = BodyHeader.size

    mod_fp.write(header.pack())

    # If signing is requested, reserve a hunk for the signature
    if signkey is not None:
        for i in range(HUNK_COUNT):
            hunk = hunks[i][0]
            if hunk.type == HUNK_EMPTY:
                hunk.type = HUNK_SIGNATURE
                hunk.flags = HUNK_RSA_PKCS1 | HUNK_SHA256
                break
        else:
            raise ValueError('signing is required but no free hunk for signature')

    # Read hunk data and write out hunk headers
    offset = header.hdr_len + header.body_len
    for hunk, fp in hunks:
        if hunk.type == HUNK_EMPTY:
            hunk.data = None
        elif hunk.type == HUNK_SIGNATURE:
            hunk.data = None
            hunk.offset = offset
            hunk.length = 0x300
        else:
            hunk.data = fp.read()
            hunk.crc = crc32(hunk.data, 0) & 0xFFFFFFFF
            hunk.offset = offset
            hunk.length = len(hunk.data)
            offset = ((offset + hunk.length) + 3) & (~3)
        mod_fp.write(hunk.pack())
        
    # Write sha256 hashes
    for hunk, fp in hunks:
        if hunk.data is not None:
            mod_fp.write(sha256(hunk.data).hexdigest().encode())
        mod_fp.write(b"\x00")

    mod_fp.seek(header.hdr_len)
    body = BodyHeader()
    body.state = state
    body.tries = 0x0F
    body.magic = MODHDR_MAGIC
    mod_fp.write(body.pack())

    mod_fp.seek(0)
    header.crc = crc32(mod_fp.read(header.hdr_len), 0) & 0xFFFFFFFF
    mod_fp.seek(0)
    mod_fp.write(header.pack())
    
    # Compute header sha256 for signing
    if signkey is not None:
        mod_fp.seek(0)
        digest = sha256(mod_fp.read(header.hdr_len)).digest()
        # TODO: actual signing...
        signature = b"\xDE"*0x300
    
    # Write data out
    for hunk, path in hunks:
        mod_fp.seek(hunk.offset)
        if hunk.type == HUNK_EMPTY:
            pass
        elif hunk.type == HUNK_SIGNATURE:
            mod_fp.write(signature)
        else:
            mod_fp.write(hunk.data)

# Command implementations

def do_inspect(args):
    info(args.infile)

def do_extract(args):
    extract(args.infile)

def do_build(args):
    state_map = {'pending': MODHDR_PENDING, 'active': MODHDR_ACTIVE, 'retired': MODHDR_RETIRED}
    type_map = {'uboot': HUNK_UBOOT_UIMAGE, 'kernel': HUNK_KERNEL_UIMAGE, 'squashfs': HUNK_FS_SQUASHFS, 'private': HUNK_PRIVATE}

    if len(args.sources) != len(args.types):
        raise ValueError('length mismatch between sources and types')
    if args.versions and len(args.sources) != len(args.versions):
        raise ValueError('length mismatch between sources and versions')
    if args.flags and len(args.sources) != len(args.flags):
        raise ValueError('length mismatch between sources and flags')

    hunks = [(HunkHeader(), None) for _ in range(HUNK_COUNT)]
    for i in range(len(args.sources)):
        header = HunkHeader()
        header.type = type_map[args.types[i]]
        if args.versions:
            header.version = args.versions[i].encode()
        if args.flags:
            header.flags = args.flags[i]
        hunks[i] = (header, args.sources[i])
    build(args.outfile, args.version, state_map[args.state], hunks, args.sign_with)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Inspect, unpack, and build MOD files.')
    parser.set_defaults(func=lambda x: parser.print_help())
    subparsers = parser.add_subparsers(help='sub-command help')

    subparser = subparsers.add_parser('inspect', help='inspect a MOD file')
    subparser.add_argument('infile', type=argparse.FileType('rb'))
    subparser.set_defaults(func=do_inspect)

    subparser = subparsers.add_parser('extract', help='extract a MOD file')
    subparser.add_argument('infile', type=argparse.FileType('rb'))
    subparser.set_defaults(func=do_extract)

    subparser = subparsers.add_parser('build', help='build a MOD file')
    subparser.add_argument('outfile', type=argparse.FileType('w+b'))
    subparser.add_argument('--version', type=str, required=True)
    subparser.add_argument('--state', type=str, choices=['pending', 'active', 'retired'], default='pending')
    subparser.add_argument('--sources', type=argparse.FileType('rb'), nargs='+', required=True, metavar='FILE')
    subparser.add_argument('--types', type=str, nargs='+', required=True, metavar='TYPE', choices=['uboot', 'kernel', 'squashfs', 'private'])
    subparser.add_argument('--versions', type=str, nargs='+', metavar='VERSION')
    subparser.add_argument('--flags', type=int, nargs='+')
    subparser.add_argument('--sign-with', type=argparse.FileType('r'), metavar='RSAKEY')
    subparser.set_defaults(func=do_build)

    args = parser.parse_args()
    args.func(args)

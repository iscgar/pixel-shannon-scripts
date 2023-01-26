#!/usr/bin/env python

# Dump the NV items registry from binary images of the MAIN modem app for Samsung
# modems. This script requires knowing the exact offset where the descriptors are
# stored in the binary. It'll try to guess the offset if it's not provided, but
# this takes time and depends on having a patched version of ahocorasick_rs
# installed, so you might want to reverse engineer it manually and provide it.
#
# For Google Pixel devices (6th and 7th generation, which use Samsung modems),
# it's quite easy to reverse engineer that location by first finding the location
# of the Confseq_fields protobuf descriptor and following the code that references
# it. The location of the protobuf descriptor can be determined by running the
# unpack_pb_descs.py script and looking for a descriptor with the follwoing structure
# in the generated output (actual message names will be different for different
# firmware images):
#
# message m15fc95 {
#     optional string f1 = 1 [(nanopb).max_size = 64];
#     optional string f2 = 2 [(nanopb).max_size = 64];
#     repeated m39a785 f3 = 3 [(nanopb).type = FT_CALLBACK];
#     repeated m1a882c f4 = 4 [(nanopb).type = FT_CALLBACK];
# }
#
# The code that uses the descriptor of this message is decoding a confseq, and is
# setting a callback for decoding the field with tag 4 (due to the FT_CALLBACK
# annotation), which is the NV Item message. That NV Item decoding callback is
# decoding into a message which has the following structure:
#
# message m1a882c {
#     optional uint32 f1 = 1;
#     repeated m1a87c8 f2 = 2 [(nanopb).type = FT_CALLBACK];
# }
#
# The field with tag 1 identifies the NV Item by a hash (which is the result of
# calculating CRC-32 on the NV Item's name). The field with tag 2 contains write
# instructions on setting the NV Item, and is decoded by a callback function which
# is set by the NV Item decoding callback before it calls `pb_decode()` (in the
# firmware that I analysed there's a check that selects between two callbacks,
# which do exactly the same thing for decoding, and only slightly differ in the
# way they use the decoded NV Item Instruction). The NV Item Instruction message
# has the following structure:
#
# message m1a87c8 {
#     optional uint32 f1 = 1;
#     optional uint32 f2 = 2;
#     optional uint64 f3 = 3;
# }
#
# The NV Item Instruction decoding callback calls a function which performs a
# lookup of the NV Item descriptor index based on the hash, and then calls a series
# of functions for getting the descriptor information, with the descriptor index
# given as an argument. Each of those function accesses the NV items registry, which
# is how you get the offset that this script requires.

# NOTE: Some firmwareimages have about 70K descriptors in the registry, so this
# will create a huge JSON file (~14MiB from the firmware that I analysed).

import binascii
import json
import os
import struct
import sys


class NvItemEntry(object):
    _FMT = struct.Struct(
        '<I'  # Name pointer
        'I'  # Element size
        'B'  # Stack divisor?
        'H'  # Element count
        'B'  # Unknown
        'I'  # Type pointer
        )
    SIZE = _FMT.size

    def __init__(self, data):
        self.name, self.elsize, self.stack_div, self.elcount, self.unknown, self.type = self._FMT.unpack(data)


def read_str(dio, offset):
    dio.seek(offset)
    s = b''
    for b in iter(lambda: dio.read(100), b''):
        try:
            s += b[:b.index(b'\x00')]
            break
        except KeyError:
            s += b
    return s.decode('utf-8')


def dump_nv_item_registry(dio, offset, ref_base):
    dio.seek(offset, os.SEEK_SET)

    entries = []
    for chunk in iter(lambda: dio.read(NvItemEntry.SIZE * 10000), b''):
        for start in range(0, len(chunk), NvItemEntry.SIZE):
            entry = NvItemEntry(chunk[start:start+NvItemEntry.SIZE])
            if entry.name == 0:
                break
            if entry.name < ref_base:
                raise ValueError('{:08x}: Entry name points to invalid location ({:08x})'.format(dio.tell() + start, entry.name))
            if entry.type < ref_base:
                raise ValueError('{:08x}: Entry type points to invalid location ({:08x})'.format(dio.tell() + start, entry.type))
            if entry.elsize == 0:
                raise ValueError('{:08x}: Entry elsize is 0'.format(dio.tell() + start))
            if entry.elcount == 0:
                raise ValueError('{:08x}: Entry elcount is 0'.format(dio.tell() + start))
            entry.name -= ref_base
            entry.type -= ref_base
            entries.append(entry)
        else:
            continue
        break

    # Intern the type names in order to avoid redundant seeks and tiny reads
    type_interned = {}
    for i, entry in enumerate(entries):
        entry.name = read_str(dio, entry.name)
        tp = type_interned.get(entry.type)
        if not tp:
            tp = read_str(dio, entry.type)
            type_interned[entry.type] = tp
        entry.type = tp

    return [{
            'id': i,
            "hash": binascii.crc32(e.name.encode('utf-8')),
            'name': e.name,
            'elsize': e.elsize,
            'stack_div': e.stack_div,
            'elcount': e.elcount,
            'unknown': e.unknown,
            'type': e.type,
        } for i, e in enumerate(entries)]


def guess_nv_registry_offset(dio, ref_base):
    # This is a best-effort attempt at finding the offset of the NV items registry
    # by looking for references to the known type names in the binary and trying
    # to parse them as valid NV item entries. Since this reads the entire image
    # into memory and searches through it, this takes some time and is quite a
    # resource hog in terms of CPU and memory usage.

    import ahocorasick_rs  # Requires a patched ahocorasick_rs that accepts bytes

    # This is a two pass process, and we need the entire image data in memory
    data = dio.read()

    # First pass: find the offsets of the type names that we know about
    TYPES = [
        b'bool\x00', b'char\x00', b'uint\x00', b's8\x00', b's16\x00',
        b's32\x00', b's64\x00', b'u8\x00', b'u16\x00', b'u32\x00', b'u64\x00']
    a = ahocorasick_rs.AhoCorasick(TYPES, matchkind=ahocorasick_rs.MATCHKIND_LEFTMOST_LONGEST)
    offsets = [struct.pack('<I', ref_base + start) for _, start, _ in a.find_matches_as_indexes(data)]

    # Second pass: look for references to the addresses of the type names
    a = ahocorasick_rs.AhoCorasick(offsets)
    first_end_offset = -1
    last_offset = -1
    count = 0
    for _, _, end in a.find_matches_as_indexes(data, overlapping=True):
        # The registry is aligned to 4-byte boundary
        if end % 4 != 0:
            continue

        # Ignore invalid entries
        entry = NvItemEntry(data[end-NvItemEntry.SIZE:end])
        if not entry.name or entry.name < ref_base or entry.elsize == 0 or entry.elcount == 0:
            continue

        if end - last_offset != NvItemEntry.SIZE:
            first_end_offset = end
            last_offset = end
            count = 0

        count += 1
        last_offset = end

        # Assume we found the registry if we have consistency for 2000 items
        if count >= 2000:
            break
    else:
        # We don't have enough entries to be confident. Bail out.
        return None

    # Since we store the end offset of the first entry, we need to subtract the entry size
    return first_end_offset - NvItemEntry.SIZE


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=argparse.FileType('rb'), help='Path to the extracted MAIN part from the modem firmware')
    parser.add_argument('-l', '--load_address', type=lambda s: int(s, 16), required=True, help='The load address of MAIN')
    parser.add_argument('-f', '--registry-offset', type=lambda s: int(s, 16), default=None, help='The offset of the NV items registry in the binary')
    args = parser.parse_args()

    if args.registry_offset is None:
        args.registry_offset = guess_nv_registry_offset(args.binary, args.load_address)
        if args.registry_offset is None:
            raise SystemExit('Failed to find the NV items registry offset')
        args.binary.seek(0, os.SEEK_SET)

    entries = dump_nv_item_registry(args.binary, args.registry_offset, args.load_address)
    json.dump(entries, sys.stdout, indent=4)

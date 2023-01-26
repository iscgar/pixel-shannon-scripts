#!/usr/env/bin python

# Decode the carrier confpack configuration files that are stored under the
# /vendor/firmware/carrierconfig path on the 6th- and 7th-series Google Pixel
# phones (which use Samsung modems, S5123 and S5300, respectively) and dump them
# into a human-readable format (JSON), so that they can be studied and potentially
# edited to support carriers that are not officially supported by Google.
#
# This requires having a dump of the NV items registry from the modem firmware
# that is paired with the confpack (this can be done using the dump_nv_descs.py
# script). Without the NV items registry we have no way to assign meaning to the
# values that we decode.

from __future__ import print_function
import argparse
import binascii
import confpack_pb2
import enum
import json
from lz4.block import decompress
import string
import struct
import os
import sys


class ConfseqType(enum.IntEnum):
    common = 0
    sim1 = enum.auto()
    sim2 = enum.auto()
    multislot = enum.auto()
    blob = enum.auto()


CLZ4_FMT = struct.Struct(
    '<I'  # Magic b'CLZ4'
    'I'  # Uncompressed size
    'I'  # Compressed size
    'I'  # Unknown checksum value (not checked by the modem's firmware)
    )


def decompress_clz4(data):
    _, uncompressed_size, compressed_size, _ = CLZ4_FMT.unpack(data[:CLZ4_FMT.size])
    compressed_data = data[CLZ4_FMT.size:CLZ4_FMT.size+compressed_size]
    return decompress(compressed_data, uncompressed_size=uncompressed_size)


def decode_confseq(confseq_path, desc):
    with open(confseq_path, 'rb') as inf:
        d = inf.read()
        if desc.ssid_group == ConfseqType.blob:
            return d  # Binary blob, not a protobuf

        if d.startswith(b'CLZ4'):
            d = decompress_clz4(d)

        c = confpack_pb2.Confseq()
        try:
            c.ParseFromString(d)
        except Exception:
            print('failure in confseq file {}'.format(f), file=sys.stderr)
            raise
        return c


def decode_manifests_and_confseqs(confpack_dir):
    manifests_path = os.path.join(confpack_dir, 'manifests')
    confseqs_path = os.path.join(confpack_dir, 'confseqs')

    if not os.path.isdir(manifests_path):
        raise ValueError('Manifests directory not found in {}'.format(manifests_path))

    if not os.path.isdir(confseqs_path):
        raise ValueError('Confseqs directory not found in {}'.format(confseqs_path))

    confseqs = {}
    manifests = {}
    for root, dirs, files in os.walk(manifests_path):
        # Do not recurse into directories
        del dirs[:]

        for f in files:
            with open(os.path.join(root, f), 'rb') as inf:
                m = confpack_pb2.CarrierManifest()
                m.ParseFromString(inf.read())
                manifests[f] = m
                for cs in m.confseqs:
                    cs_hash = binascii.hexlify(cs.confseq_truncated_sha256).decode('utf-8')
                    if cs.ssid_group not in ConfseqType.__members__.values():
                        raise ValueError('{} ({}): invalid confseq type {}'.format(f, m.name, cs_hash, cs.ssid_group))
                    decoded_cs = confseqs.get(cs_hash)
                    if not decoded_cs:
                        try:
                            confseqs[cs_hash] = decode_confseq(os.path.join(confseqs_path, cs_hash), cs)
                        except Exception as e:
                            raise ValueError('{} ({}): failed to decode confseq {}: {}'.format(f, m.name, cs_hash, e))

    return (manifests, confseqs)


def dump_manifests(manifests, confseqs, out_manifests_path):
    os.makedirs(out_manifests_path, exist_ok=True)

    for manifest in manifests.values():
        m_desc = {
            'revision': manifest.revision, 'name': manifest.name,
            'carrier_id': manifest.carrier_id, 'confseqs': []}
        if manifest.HasField('oldest_compat_modem'):
            m_desc['oldest_compat_modem'] = manifest.oldest_compat_modem
        for csd in manifest.confseqs:
            cs_hash = binascii.hexlify(csd.confseq_truncated_sha256).decode('utf-8')
            cs_desc = {'type': ConfseqType(csd.ssid_group).name, 'hash': cs_hash}
            if csd.ssid_group != ConfseqType.blob:
                cs_desc['name'] = confseqs[cs_hash].name
            for attr in ('f3', 'f4', 'blob_path', 'platform', 'product'):
                if csd.HasField(attr):
                    cs_desc[attr] = getattr(csd, attr)
            m_desc['confseqs'].append(cs_desc)

        with open(os.path.join(out_manifests_path, '{}.json'.format(m_desc['name'])), 'w') as of:
            json.dump(m_desc, of, indent=2)


def convert_in_range(v, first, last, converter):
    if not (first <= v <= last):
        raise ValueError('value {} is outside the range [{},{}]'.format(v, first, last))
    return converter(v)


def uint_to_sint_converter(bits):
    assert bits > 1
    sign_bit = 1 << (bits - 1)
    mask = (sign_bit << 1) - 1
    neg_mask = ((1 << (64 - (bits - 1))) - 1) ^ (sign_bit - 1)
    def converter(v):
        if v < 0:
            raise ValueError('got a signed value {}'.format(v))
        if v > mask:
            if (v & sign_bit) == 0:
                raise ValueError('value is bigger than max value ({:x} > {:x})'.format(v, mask))
            if (v & neg_mask) != neg_mask:
                raise ValueError('value is not fully sign extended ({:x} & {:x} == {:x})'.format(v, neg_mask, v & neg_mask))
        return (v & mask) - ((v & sign_bit) << 1)
    return converter


def dump_confseqs(confseqs, out_confseqs_path, nv_registry_path):
    with open(nv_registry_path, 'rb') as f:
        nv_registry = {e['hash']: e for e in json.load(f)}

    os.makedirs(out_confseqs_path, exist_ok=True)

    TYPE_CONVERTERS = {
        'bool': lambda i: convert_in_range(i, 0, 1, bool),
        'char': lambda i: convert_in_range(i, 0, 255, chr),
        'uint': lambda i: convert_in_range(i, 0, 0xffffffff, int),
        's8': uint_to_sint_converter(8),
        's16': uint_to_sint_converter(16),
        's32': uint_to_sint_converter(32),
        's64': uint_to_sint_converter(64),
        'u8': lambda i: convert_in_range(i, 0, 0xff, int),
        'u16': lambda i: convert_in_range(i, 0, 0xffff, int),
        'u32': lambda i: convert_in_range(i, 0, 0xffffffff, int),
        'u64': lambda i: convert_in_range(i, 0, 0xffffffffffffffff, int),
    }
    PRINTABLE = set(string.printable.encode('ascii'))

    for cs_hash, cs in confseqs.items():
        # Write raw certificates directly (no change)
        if isinstance(cs, bytes):
            with open(os.path.join(out_confseqs_path, cs_hash), 'wb') as of:
                of.write(cs)
            continue

        cs_desc = {'revision': cs.revision, 'name': cs.name, 'items': []}
        for item_idx, item in enumerate(cs.nv_items):
            desc = nv_registry[item.nv_item_hash]
            if all(w.start_seq == w.count == 0 for w in item.writes):
                try:
                    writes = [TYPE_CONVERTERS[desc['type']](w.value) for w in item.writes]
                except ValueError:
                    print('failure while processing write {}->{}({})->{} of type {} with value {:x}'.format(
                        cs.name, desc['name'], item_idx, w_idx, desc['type'], w.value), file=sys.stderr)
                    print('elsize={}, elcount={}, stack_div={}, w.count={}'.format(
                        desc['elsize'], desc['elcount'], desc['stack_div'], w.count), file=sys.stderr)
                    raise
                # Special case for strings which seem to be defined as u8 arrays rather than char arrays:
                # Check if descriptor might be a candidate for string conversion
                if len(writes) > 1 and desc['elsize'] == 1 and desc['type'] == 'u8' and desc['elcount'] / desc['stack_div'] > 1:
                    # Check if the write is a string
                    # Some are NUL terminated, some not. If NUL terminated, require more than a single printable character.
                    if all(w in PRINTABLE for w in writes[:-1]) and (writes[-1] in PRINTABLE or len(writes) > 2 and writes[-1] == 0):
                        writes = ''.join(chr(w) for w in writes)
            else:
                writes = []
                for w_idx, w in enumerate(item.writes):
                    try:
                        writes.append({
                            'seq': w.start_seq,
                            'value': TYPE_CONVERTERS[desc['type']](w.value),
                            'count': w.count,
                        })
                    except ValueError:
                        print('failure while processing write {}->{}({})->{} of type {} with value {:x}'.format(
                            cs.name, desc['name'], item_idx, w_idx, desc['type'], w.value), file=sys.stderr)
                        print('elsize={}, elcount={}, stack_div={}, w.count={}'.format(
                            desc['elsize'], desc['elcount'], desc['stack_div'], w.count), file=sys.stderr)
                        raise
            cs_desc['items'].append({'name': desc['name'], 'writes': writes})

        with open(os.path.join(out_confseqs_path, '{}.json'.format(cs_desc['name'])), 'w') as of:
            json.dump(cs_desc, of, indent=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('confpack_dir', help='The path to the confpack directory, containing the manifests and confseqs directories')
    parser.add_argument('-r', '--nv-registry-file', required=True, help='The path to a dumped NV items registry JSON file')
    parser.add_argument('-o', '--out-dir', required=True, help='The path to an output directory, where decoded outputs will be saved')
    args = parser.parse_args()

    manifests, confseqs = decode_manifests_and_confseqs(args.confpack_dir)
    dump_manifests(manifests, confseqs, os.path.join(args.out_dir, 'manifests'))
    dump_confseqs(confseqs, os.path.join(args.out_dir, 'confseqs'), args.nv_registry_file)

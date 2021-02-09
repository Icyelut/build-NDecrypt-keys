# aeskeydb to NDecrypt
# main.py
# Copyright 2021-02-09 - Icyelut. GPLv3

import argparse
import os
import pathlib
import codecs
import hashlib
import sys

hardware_constant_hash = "05d6564396705f79890a12cd05dd914b0adc01ccaa4d5158a90bb32553025997"
KeyX0x18_hash = "76c76b655db85219c5d35d517ffaf7a43ebad66e31fbdd5743925937a893ccfc"
KeyX0x1B_hash = "9a201e7c3737f3722e5b578d11837f197ca65bf52625b2690693e4165352c6bb"
KeyX0x25_hash = "7e878dde92938e4c717dd53d1ea35a75633f5130d8cfd7c76c8f4a8fb87050cd"
KeyX0x2C_hash = "585b02cd02ab39afd91ebe4a2189070e50c93df5ba5461eb91782910ecacb282"
DevKeyX0x18_hash = "08e10962f65a09aa122c7cbedea19c4b5c9a8ac3d98ea1620411d7e85570a6c2"
DevKeyX0x1B_hash = "a53c3e5d095c733521793f2e4c10caae87835153460b52399b0062f639cb6216"
DevKeyX0x25_hash = "c40431c7f5cf6faa63ae592c6c4bb25b7158dc3b6dcaf44ccd247454e3683ede"
DevKeyX0x2C_hash = "d17a435ef18ceef79b01756965cf9945d77a4713fd636de8aba05a8710fce373"


def write_keys_bin(keys_bin_filepath, keys_dict):
    key_names = ["Hardware constant",
                 "KeyX0x18", "KeyX0x1B", "KeyX0x25", "KeyX0x2C",
                 "DevKeyX0x18", "DevKeyX0x1B", "DevKeyX0x25", "DevKeyX0x2C"]
    blank = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    with codecs.open(keys_bin_filepath, "wb") as outfile:
        for key_name in key_names:
            if key_name in keys_dict.keys():
                print(f"Writing key '{key_name}' to keys.bin...")
                outfile.write(keys_dict[key_name])
            else:
                print(f"[WARNING] Key {key_name} not found. Filling with zeroes...")
                outfile.write(blank)


def bytes_reverse(byte_string):
    return bytes(list(reversed(byte_string)))


def get_keybin_path(args):
    if args.outpath:
        keys_bin_path = args.outpath
    else:
        if parsed_args.aeskeydb:
            source_file_path = args.aeskeydb
        else:
            source_file_path = args.aeskeystxt

        resolved_path = pathlib.Path(source_file_path).resolve(strict=True).expanduser()
        working_directory = os.path.split(resolved_path)[0]
        keys_bin_path = os.path.join(working_directory, "keys.bin")

        return keys_bin_path


def run_aeskeydb(args):

    keys = []
    with codecs.open(args.aeskeydb, "rb") as infile:
        bytes = infile.read(32)
        while(bytes):
            key_metadata = bytes[0:16]
            key = bytes[16:32]
            keyhash = hashlib.sha256(key).hexdigest()
            keys.append((key_metadata, key, keyhash))
            bytes = infile.read(32)

    keys_dict = dict()
    for key_metadata, key, keyhash in keys:
        key_little_endian = bytes_reverse(key)
        if keyhash == hardware_constant_hash:
            keys_dict["Hardware constant"] = key_little_endian
        elif keyhash == KeyX0x18_hash:
            keys_dict["KeyX0x18"] = key_little_endian
        elif keyhash == KeyX0x1B_hash:
            keys_dict["KeyX0x1B"] = key_little_endian
        elif keyhash == KeyX0x25_hash:
            keys_dict["KeyX0x25"] = key_little_endian
        elif keyhash == KeyX0x2C_hash:
            keys_dict["KeyX0x2C"] = key_little_endian
        elif keyhash == DevKeyX0x18_hash:
            keys_dict["DevKeyX0x18"] = key_little_endian
        elif keyhash == DevKeyX0x1B_hash:
            keys_dict["DevKeyX0x1B"] = key_little_endian
        elif keyhash == DevKeyX0x25_hash:
            keys_dict["DevKeyX0x25"] = key_little_endian
        elif keyhash == DevKeyX0x2C_hash:
            keys_dict["DevKeyX0x2C"] = key_little_endian

    return keys_dict


def run_aeskeystxt(args):
    keys_dict = dict()
    with codecs.open(args.aeskeystxt, "r", "utf8") as infile:
        for line in infile:
            key_name, key = line.split("=")
            key_little_endian = bytes_reverse(bytes.fromhex(key))
            keyhash = hashlib.sha256(bytes.fromhex(key)).hexdigest()
            if keyhash == hardware_constant_hash:
                keys_dict["Hardware constant"] = key_little_endian
            elif keyhash == KeyX0x18_hash:
                keys_dict["KeyX0x18"] = key_little_endian
            elif keyhash == KeyX0x1B_hash:
                keys_dict["KeyX0x1B"] = key_little_endian
            elif keyhash == KeyX0x25_hash:
                keys_dict["KeyX0x25"] = key_little_endian
            elif keyhash == KeyX0x2C_hash:
                keys_dict["KeyX0x2C"] = key_little_endian
            elif keyhash == DevKeyX0x18_hash:
                keys_dict["DevKeyX0x18"] = key_little_endian
            elif keyhash == DevKeyX0x1B_hash:
                keys_dict["DevKeyX0x1B"] = key_little_endian
            elif keyhash == DevKeyX0x25_hash:
                keys_dict["DevKeyX0x25"] = key_little_endian
            elif keyhash == DevKeyX0x2C_hash:
                keys_dict["DevKeyX0x2C"] = key_little_endian

    return keys_dict

def run(args):
    aeskeydb_keys = {}
    aeskeystxt_keys = {}
    if parsed_args.aeskeydb:
        aeskeydb_keys = run_aeskeydb(args)
    if parsed_args.aeskeystxt:
        aeskeystxt_keys = run_aeskeystxt(args)

    keys_dict = {**aeskeydb_keys, **aeskeystxt_keys}

    if args.hardware_constant:
        hardware_constant_b = bytes.fromhex(args.hardware_constant)
        keys_dict["Hardware constant"] = bytes_reverse(hardware_constant_b)

    if args.KeyX0x2C:
        KeyX0x2C_b = bytes.fromhex(args.KeyX0x2C)
        keys_dict["KeyX0x2C"] = bytes_reverse(KeyX0x2C_b)

    if args.DevKeyX0x2C:
        DevKeyX0x2C_b = bytes.fromhex(args.DevKeyX0x2C)
        keys_dict["DevKeyX0x2C"] = bytes_reverse(DevKeyX0x2C_b)

    keys_bin_path = get_keybin_path(args)
    write_keys_bin(keys_bin_path, keys_dict)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Generate NDecrypt keys.bin from Godmode9's aeskeys.bin or Citra's aes_keys.txt "
                    "Checks that the correct keys have been loaded via hash."
                    "Note: If you have the standard aeskeydb.bin"
                    " (sha256 4076543DA3FF911CE1CC4EC72F92E4B72B240015BE9BFCDE7FED951DD5AB2DCB)"
                    "then you will need to additionally find generator, KeyX0x2C, and DevKeyX0x2C and supply them via "
                    "arguments --hardware_constant, --KeyX0x2C, and --DevKeyX0x2C, respectively.",
        epilog="Copyright 2021-02-09 - Icyelut. GPLv3",
        fromfile_prefix_chars='@')

    parser.add_argument("--verbose", action="store_true", help="Print all debug messages")

    parser.add_argument('--outpath', dest="outpath", help="Path for the keys.bin. If not supplied, will output in the "
                                                          "same directory as aeskeydb.bin / aes_keys.txt")

    parser.add_argument('--aeskeydb_bin', dest='aeskeydb', help="Path for the aeskeydb.bin")
    parser.add_argument('--aes_keys_txt', dest='aeskeystxt', help="Path for the aes_keys.txt")

    parser.add_argument('--hardware_constant', dest="hardware_constant", help="Hardware constant value  (big "
                                                                                       "endian), also referred to as "
                                                                                       "'generator'. Not contained in "
                                                                                       "standard aeskeydb.bin. If not "
                                                                                       "supplied, will fill with 0s")
    parser.add_argument('--KeyX0x2C', dest="KeyX0x2C", help="KeyX0x2C value  (big endian). Not contained in "
                                                                     "standard aeskeydb.bin. If not supplied, "
                                                                     "will fill with 0s")
    parser.add_argument('--DevKeyX0x2C', dest="DevKeyX0x2C", help="DevKeyX0x2C value (big endian). Not "
                                                                           "contained in standard aeskeydb.bin. If "
                                                                           "not supplied, will fill with 0s")


    parsed_args = parser.parse_args()

    if parsed_args.aeskeydb or parsed_args.aeskeystxt:
        run(parsed_args)

    else:
        print("No key files in input. Quitting.")
        parser.print_help()
        sys.exit(0)

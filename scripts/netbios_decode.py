#!/usr/bin/env python3
#
# Usage:
#
#   ./netbios_decode.py dns-beacon-127.0.0.1.dat
#
# Decoded payload will be written with a `.decoded` extensions
#
#
# Author: Yun Zheng Hu <hu@fox-it.com>

import argparse
import sys


def netbios_decode(netbios):
    def nbiter(data):
        data = bytearray(data)
        for i in range(0, len(data), 2):
            a = (data[i] - 0x41) << 4
            b = (data[i + 1] - 0x41) & 0x0F
            yield a + b

    return bytes(bytearray(nbiter(netbios.upper())))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", nargs="+")
    args = parser.parse_args()

    for fname in args.filename:
        with open(fname, "rb") as fin:
            data = fin.read()
            if not data:
                sys.stderr.write("Skipping empty file: {}\n".format(fname))
                continue
            assert b"gogo" in data, fname
            assert data.endswith(b"aa"), fname

            _shellcode, _sep, data = data.partition(b"gogo")
            data = data[0:-2]
            with open(fname + ".decoded", "wb") as fout:
                fout.write(netbios_decode(data))
            sys.stderr.write("Decoded {} -> {}.decoded\n".format(fname, fname))


if __name__ == "__main__":
    sys.exit(main())

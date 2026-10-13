#!/usr/bin/env python3
#
# Script to pull the beacon over DNS from a Cobalt Strike DNS Server
#
# /// script
# dependencies = [
#     "dnspython>=2.9.0",
# ]
# ///
#
# Usage:
#
# If you know the IP of the Cobalt Strike DNS server, override the DNS server
# using -r/--resolver to send queries directly to the C2 IP:
#
#  ./pull_dns_beacon.py -r <COBALTSTRIKE C2 IP> <COBALTSTRIKE C2 IP>
#
# If you only have the (sub)domain you can query over the default resolver (8.8.8.8):
#
#  ./pull_dns_beacon.py my.c2server.com
#
#
# Author: Yun Zheng Hu <hu@fox-it.com>
#


# Python imports
import argparse
import os
import string
import sys

# dnspython imports
import dns.exception
import dns.resolver

CHUNK_SIZE = 255
MAX_ATTEMPTS = 10


def triplet_to_int(s):
    assert len(s) == 3
    t = bytearray(s.encode())
    a = (t[0] - ord("a")) * pow(26, 0)
    b = (t[1] - ord("a")) * pow(26, 1)
    c = (t[2] - ord("a")) * pow(26, 2)
    return a + b + c


def int_to_triplet(x):
    assert 0 <= x <= triplet_to_int("zzz")
    letters = string.ascii_lowercase
    c = letters[x // (26**2) % 26]
    b = letters[x // (26**1) % 26]
    a = letters[x // (26**0) % 26]
    return a + b + c


def open_output(out_path, continue_at):
    """Open the output file and return (fh, start_index)."""
    if continue_at == "-":
        if not os.path.exists(out_path):
            raise Exception("Cannot determine index, file does not exist")
        size = os.path.getsize(out_path)
        start_index = size // CHUNK_SIZE
        # Drop a trailing partial chunk so it can be refetched cleanly.
        keep = start_index * CHUNK_SIZE
        f = open(out_path, "r+b")
        if size != keep:
            sys.stderr.write(
                "File {} has size {} (not a multiple of {}), truncating to {}\n".format(
                    out_path, size, CHUNK_SIZE, keep
                )
            )
            f.truncate(keep)
        else:
            sys.stderr.write("File {} has size: {}\n".format(out_path, size))
        f.seek(0, os.SEEK_END)
        return f, start_index

    start_index = int(continue_at)
    if start_index < 0:
        raise ValueError("continue-at index must be >= 0")
    if start_index == 0:
        return open(out_path, "wb"), start_index

    # Resume from an explicit index without wiping already-downloaded chunks.
    if os.path.exists(out_path):
        size = os.path.getsize(out_path)
        expected = start_index * CHUNK_SIZE
        if size != expected:
            sys.stderr.write(
                "Warning: {} is {} bytes, expected {} for index {}\n".format(out_path, size, expected, start_index)
            )
        f = open(out_path, "ab")
    else:
        f = open(out_path, "wb")
    return f, start_index


def resolve_txt(resolver, query, domain, index):
    """Resolve a single TXT record, retrying timeouts. Never reuse a prior answer."""
    answers = None
    last_timeout = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            answers = resolver.resolve(query, "TXT")
            break
        except dns.exception.Timeout as exc:
            last_timeout = exc
            sys.stderr.write("Got DNS timeout for {} at index {}, retrying..({})\n".format(domain, index, attempt))
    else:
        raise dns.exception.Timeout(
            "exhausted {} retries for {!r} at index {}".format(MAX_ATTEMPTS, query, index)
        ) from last_timeout

    if answers is None or len(answers) != 1:
        raise RuntimeError(
            "expected 1 TXT answer for {!r} at index {}, got {}".format(
                query, index, 0 if answers is None else len(answers)
            )
        )
    return b"".join(answers[0].strings)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("domain", metavar="DOMAIN", help="Cobalt Strike DNS domain or IP")
    parser.add_argument(
        "-r",
        "--resolver",
        metavar="RESOLVER",
        default="8.8.8.8",
        help="Use specified DNS resolver",
    )
    parser.add_argument(
        "-C",
        "--continue-at",
        default="0",
        metavar="INDEX",
        help="Continue at index, if INDEX is '-' it will determine where to continue from",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="dns-beacon-{domain}.dat",
        help="DNS beacon output file",
    )
    args = parser.parse_args()

    resolver = dns.resolver.Resolver(configure=False)
    resolver.lifetime = 10
    resolver.timeout = 10
    resolver.nameservers = [args.resolver]

    out_path = args.output.format(domain=args.domain)
    f, start_index = open_output(out_path, args.continue_at)

    sys.stderr.write("Starting from index: {}\n".format(start_index))
    try:
        for index in range(start_index, triplet_to_int("zzz") + 1):
            triplet = int_to_triplet(index)

            query = triplet + ".stage"
            if args.domain != args.resolver:
                query += "." + args.domain

            try:
                for i in range(3):
                    txt = resolve_txt(resolver, query, args.domain, index)
                    if not txt:
                        sys.stderr.write(f"Empty TXT record for {args.domain!r} at index {index}.. retrying {i}\n")
                        continue
            except Exception:
                sys.stderr.write("Exception raised for {!r} at index {}, giving up\n".format(args.domain, index))
                raise

            if not txt:
                sys.stderr.write("Empty TXT record for {!r} at index {}\n".format(args.domain, index))
                raise RuntimeError("empty TXT payload at index {}".format(index))
            msg = "{} {}@{} = {}\n".format(index, query, args.domain, txt)
            sys.stderr.write(msg)
            f.write(txt)
            f.flush()
            if len(txt) < CHUNK_SIZE:
                break
    finally:
        f.close()


if __name__ == "__main__":
    sys.exit(main())

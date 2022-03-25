#!/usr/bin/env python3
#
# Simple script to check the checksum8 of accesslogs
#
import re
import sys
import datetime
import argparse
import collections

from dissect.cobaltstrike import utils

RE_ACCESS_LOG = re.compile(
    r"""
    [^\d]*                      # ignore front matter (eg: filename from grep out or logger name)
    (?P<ip>\d+\.\d+\.\d+\.\d+)  # the IP address
    .*                          # Ignore other stuff (could be a space, or username in case of nginx or apache)
    \[(?P<time>.+)\]            # the date and time
    \s+                         # ignore spaces
    "(?P<request>.*)"           # the request
    \s+                         # ignore spaces
    (?P<status>[0-9]+)          # the status
    \s+                         # ignore spaces
    (?P<size>\S+)               # the size
    \s+                         # ignore spaces
    "(?P<referrer>.*)"          # the referrer
    \s+                         # ignore spaces
    "(?P<agent>.*)"             # the user agent
""",
    re.VERBOSE,
)


def build_parser():
    parser = argparse.ArgumentParser(description="checksum8 accesslogs")
    parser.add_argument("--stats", action="store_true", help="show monthly stats")
    parser.add_argument("-l", "--length", type=int, help="truncate output to this length")
    parser.add_argument("-b", "--brief", action="store_true", help="brief output (no user agent)")
    parser.add_argument("-d", "--datefmt", default=None, help="date format")
    return parser


@utils.catch_sigpipe
def main():
    parser = build_parser()
    args = parser.parse_args()

    stats = collections.Counter()

    print("[reading from stdin..]", file=sys.stderr)
    for line in sys.stdin:
        match = RE_ACCESS_LOG.match(line)
        if not match:
            continue
        ip = match.group("ip")
        apache_stamp = match.group("time")
        request = match.group("request")
        agent = match.group("agent")
        dt = datetime.datetime.strptime(apache_stamp, "%d/%b/%Y:%H:%M:%S %z")
        method, _, uri = request.partition(" ")
        uri, _, version = uri.partition(" ")
        if utils.is_stager_x86(uri) or utils.is_stager_x64(uri):
            beacon = "x64" if utils.is_stager_x64(uri) else "x86"
            if args.stats:
                fmt = args.datefmt or "%Y-%m"
                stats[dt.strftime(fmt)] += 1
                continue
            if args.datefmt:
                dt = dt.strftime(args.datefmt)
            if args.brief:
                out = f"{dt} - beacon {beacon} - {method} {uri}"
            else:
                out = f"{dt} - beacon {beacon} - {method} {ip} {uri} - {agent}"

            if args.length and len(out) > args.length:
                out = out[: args.length] + "..."
            print(out)

    if args.stats:
        print("date,requests")
        for month, value in sorted(stats.items()):
            print(f"{month},{value}")


if __name__ == "__main__":
    sys.exit(main())

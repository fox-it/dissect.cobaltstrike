"""
This module is responsible for dumping payloads from `ArtifactKit`_ generated executables.

.. _ArtifactKit: https://www.cobaltstrike.com/blog/what-is-a-stageless-payload-artifact/
"""
import io
import sys
import logging
import contextlib

from typing import NamedTuple, BinaryIO, Iterator, Optional

from dissect.cobaltstrike import utils

logger = logging.getLogger(__name__)


class ArtifactKitPayload(NamedTuple):
    """Namedtuple containing the ArtifactKit metadata and decoded payload"""

    offset: int
    """Offset of the ArtifactKit metadata in the file"""
    size: int
    """Size of the payload"""
    xorkey: bytes
    """4-byte random xor mask"""
    hints: bytes
    """Loader hints (GetModuleHandleA, GetProcAddress)"""
    payload: bytes
    """Decoded ArtifactKit payload"""


def iter_artifactkit_payloads(
    fobj: BinaryIO, start_offset: Optional[int] = 0, maxrange: Optional[int] = None
) -> Iterator[ArtifactKitPayload]:
    """Iterate over found :class:`ArtifactKitPayload` by scanning `fobj` for possible ArtifactKit payloads.

    Side effects: file position due to seeking

    .. note::
        No additional checks are done on the ArtifactKit payloads to ensure that what is found is actually correct.

    Args:
        fobj: file-like object
        start_offset: starting offset to search for ArtifactKit payloads,
          if `None` it will search from current offset. (default: 0)
        maxrange: maximum file offset to limit search to,
          if `None` it will search the entire file (default: `None`)

    Yields:
        :class:`ArtifactKitPayload`
    """
    if start_offset is not None:
        fobj.seek(start_offset)
    pos = fobj.tell()
    while True:
        if maxrange is not None and pos > maxrange:
            break
        fobj.seek(pos)
        data = fobj.read(4)
        if not data or len(data) != 4:
            break
        if pos + 16 == utils.u32(data):
            size = utils.u32(fobj.read(4))
            xorkey = fobj.read(4)
            hints = fobj.read(8)
            data = fobj.read(size)
            payload = utils.xor(data, xorkey)
            yield ArtifactKitPayload(offset=pos, size=size, xorkey=xorkey, hints=hints, payload=payload)
        pos += 1


@utils.catch_sigpipe
def main():
    """Entrypoint for :doc:`/tools/beacon-artifact`"""

    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input", metavar="FILE", help="FILE to decode")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbosity level (-v for INFO, -vv for DEBUG)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("wb"),
        default="-",
        help="write decoded ArtifactKit payload to FILE",
    )
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level)

    if args.input in ("-", "/dev/stdin"):
        finput = io.BytesIO(sys.stdin.buffer.read())
    else:
        finput = open(args.input, "rb")

    foutput = args.output.buffer if hasattr(args.output, "buffer") else args.output

    with contextlib.closing(finput):
        dumped = False
        for artifact in iter_artifactkit_payloads(finput):
            logger.info("FOUND possible ArtifactKit offset: %s", artifact.offset)
            logger.info("  - size: %s", artifact.size)
            logger.info("  - 4-byte xorkey: %r", artifact.xorkey)
            logger.info("  - hints: %r", artifact.hints)
            logger.info("  - payload (preview): %r", artifact.payload[:20])
            if not dumped:
                # only dump the first payload to `foutput`
                foutput.write(artifact.payload)
                dumped = True

    if not dumped:
        return f"{args.input}: No ArtifactKit payload found"

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
This module is responsible for decoding XorEncoded Cobalt Strike payloads.
Not to be confused with the single byte XOR key that is used to obfuscate the beacon configuration block.
"""

from __future__ import annotations

import contextlib
import io
import logging
import sys
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from typing import Iterator

from dissect.util.stream import RangeStream

from dissect.cobaltstrike.utils import catch_sigpipe, u32, xor

logger = logging.getLogger(__name__)

# Trailing padding after the encoded payload (custom stubs often leave a few extra bytes).
# Stock CS is exact; keep the slack small.
# Reference sample that has some slack: dc7fa7c67f059f792f69ae46d31413030fd034cd045765d145836246341bf968
_MIN_DECODED_SIZE = 0x200
_MAX_TRAILER = 256


def _xor_bytes(a, b):
    """XOR two equal-length byte strings at C speed via big integers."""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def iter_nonce_offsets(fh: BinaryIO, real_size: int | None = None, maxrange: int = 1024) -> Iterator[int]:
    """Returns a generator that yields nonce offset candidates based on encoded real_size.

    If real_size is None it will automatically determine the size from fh.
    It tries to find the `nonce offset` using the following structure.

       ``| nonce (dword) | encoded_size (dword) | encoded MZ + payload |``

    Side effects: file handle position due to seeking

    Args:
        fh: file like object
        real_size: encoded_size to search for, or automatically determined from fh if None.
        maxrange: maximum range to search for

    Yields:
        nonce_offset candidates
    """
    if real_size is None:
        fh.seek(0, io.SEEK_END)
        real_size = fh.tell()

    for i in range(maxrange):
        fh.seek(i)
        nonce = fh.read(4)
        size = fh.read(4)
        if len(nonce) != 4 or len(size) != 4:
            break
        decoded_size = u32(xor(nonce, size))
        encoded_end = decoded_size + i + 8
        if decoded_size < _MIN_DECODED_SIZE or encoded_end > real_size:
            continue
        if encoded_end == real_size:
            logger.debug("FOUND real_size, iter_nonce_offsets -> %u", i)
            yield i
        elif (real_size - encoded_end) <= _MAX_TRAILER:
            logger.debug("FOUND real_size with slack (%d), iter_nonce_offsets -> %u", real_size - encoded_end, i)
            yield i


class XorEncodedFile(io.RawIOBase):
    _fp: BinaryIO = None

    def __init__(self, fp: BinaryIO, nonce: bytes) -> None:
        assert len(nonce) == 4, "Nonce must be 4 bytes long"
        self._fp = fp
        self._nonce = nonce  # permanent - never changes
        self._prev = nonce  # rolls forward, reset on seek
        self._base = fp.tell() if fp.seekable() else 0

    def get_name(self) -> str:
        return "XorEncodedFile"

    @classmethod
    def from_file(cls, fh: BinaryIO, nonce_offset: int | None = None, maxrange: int = 1024) -> "XorEncodedFile":
        """Constructs a XorEncodedFile from file `fh` as it's current nonce_offset.

        Args:
            fh: file-like object
            nonce_offset: offset of the nonce in the file, if None it will try to find it automatically
            maxrange: maximum range to search for nonce_offset if nonce_offset is None

        Raises:
            ValueError: if nonce_offset is None and no valid nonce offset could be found

        Returns:
            XorEncodedFile instance
        """
        if nonce_offset is None:
            nonce_offsets = list(iter_nonce_offsets(fh, real_size=None, maxrange=maxrange))
            if not nonce_offsets:
                raise ValueError("Could not find a valid nonce offset")
            nonce_offset = nonce_offsets[0]
            logger.debug("Found nonce offset: %d", nonce_offset)

        fh.seek(nonce_offset)
        nonce = fh.read(4)
        encoded_size = fh.read(4)
        _real_size = _xor_bytes(nonce, encoded_size)
        fh.seek(0, io.SEEK_END)
        file_end = fh.tell()
        range_size = file_end - (nonce_offset + 8)
        return cls(RangeStream(fh, offset=nonce_offset + 8, size=range_size), nonce=nonce)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return self._fp.seekable()

    def tell(self) -> int:
        return self._fp.tell() - self._base

    def readinto(self, b) -> int:
        mv = memoryview(b)
        raw = self._fp.read(len(mv))
        if not raw:
            return 0
        combined = self._prev + raw
        out = _xor_bytes(combined[4:], combined[:-4])
        self._prev = combined[-4:]
        mv[: len(out)] = out
        return len(out)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if not self.seekable():
            raise io.UnsupportedOperation("seek")
        if whence == io.SEEK_SET:
            p = offset
        elif whence == io.SEEK_CUR:
            p = self.tell() + offset
        elif whence == io.SEEK_END:
            p = (self._fp.seek(0, io.SEEK_END) - self._base) + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if p < 0:
            raise OSError("negative seek position")
        n = len(self._nonce)
        start = max(0, p - n)
        self._fp.seek(self._base + start)
        window = self._fp.read(p - start)
        if p < n:
            window = self._nonce[p:] + window  # straddles nonce boundary
        self._prev = window
        self._fp.seek(self._base + p)
        return p

    def close(self) -> None:
        if not self.closed and self._fp is not None:
            self._fp.close()
        super().close()


@catch_sigpipe
def main():
    """Entrypoint for :doc:`/tools/beacon-xordecode`"""
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input", metavar="FILE", help="FILE to decode")
    parser.add_argument(
        "-n",
        "--nonce-offset",
        default=None,
        type=int,
        help="Force nonce offset (instead of auto detecting)",
    )
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
        help="write decoded payload to FILE",
    )
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level)

    from dissect.cobaltstrike.pe import (
        find_architecture,
        find_compile_stamps,
        find_magic_mz,
        find_magic_pe,
        find_stage_prepend_append,
    )

    logger.info("Processing file: {!r}".format(args.input))
    fout = args.output.buffer if hasattr(args.output, "buffer") else args.output
    if args.input in ("-", "/dev/stdin"):
        fin = io.BytesIO(sys.stdin.buffer.read())
    else:
        fin = open(args.input, "rb")

    with contextlib.closing(fin):
        if args.nonce_offset is not None:
            fxor = XorEncodedFile.from_file(fin, nonce_offset=args.nonce_offset)
        else:
            fxor = XorEncodedFile.from_file(fin)
            if not fxor:
                return f"Not a xorencoded file: {args.input}"

        logger.info(f"magic mz: {find_magic_mz(fxor)}")
        logger.info(f"magic pe: {find_magic_pe(fxor)}")
        logger.info(f"architecture: {find_architecture(fxor)}")
        logger.info(f"compile stamps: {find_compile_stamps(fxor)}")
        logger.info(f"stage prepend+append: {find_stage_prepend_append(fxor)}")

        fxor.seek(0)
        while True:
            data = fxor.read(io.DEFAULT_BUFFER_SIZE)
            if not data:
                break
            fout.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())

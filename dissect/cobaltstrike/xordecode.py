"""
This module is responsible for decoding XorEncoded Cobalt Strike payloads.
Not to be confused with the single byte XOR key that is used to obfuscate the beacon configuration block.
"""
import io
import os
import sys
import logging
import collections
from typing import BinaryIO, Iterator, Union, cast

from dissect.cobaltstrike.utils import catch_sigpipe, iter_find_needle, xor, u32
from . import pe

logger = logging.getLogger(__name__)


def iter_nonce_offsets(fh: BinaryIO, real_size: int = None, maxrange: int = 1024) -> Iterator[int]:
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
        if decoded_size + i + 8 == real_size:
            logger.debug("FOUND real_size, iter_nonce_offsets -> %u", i)
            yield i


class XorEncodedFile(io.RawIOBase):
    """A file object providing transparant decoding of XorEncoded files.

    To verify if a file is a XorEncoded Beacon, use the :meth:`XorEncodedFile.from_file()` constructor
    which raises ``ValueError`` if it cannot find a nonce candidate or valid MZ header.

    To skip any validation checks, construct via :meth:`XorEncodedFile` using `nonce_offset`.
    """

    EOF_SHELLCODE_MARKER = b"\xff\xff\xff"

    def __init__(self, fh: BinaryIO, nonce_offset: int = 0) -> None:
        self.fh = fh
        self.nonce_offset = nonce_offset

        self.fh.seek(self.nonce_offset)
        self.initial_nonce = self.fh.read(4)
        self.nonced_filesize = self.fh.read(4)

    def __repr__(self) -> str:
        return f"<XorEncodedFile fh={self.fh}, nonce_offset={self.nonce_offset}>"

    @classmethod
    def from_file(cls, fh: BinaryIO, maxrange: int = 1024) -> "XorEncodedFile":
        """Constructs a XorEncodedFile from file `fh`, raises ValueError if file not determined as a XorEncoded Beacon.

        This constructor will try to find the correct ``nonce_offset`` by using the following methods:

         - **end of shellcode offset**: will try to find the end of the shellcode stub.
         - **real_size**: using :func:`iter_nonce_offsets()` to find candidate offsets based on size.

        The ``nonce_offset`` candidates are then checked to see if there is a valid MZ header.

        Args:
            fh: file-like object
            maxrange: how far into the file should be try to find the `nonce_offset` candidates (default 1024)

        Returns:
            XorEncodedFile instance

        Raises:
            ValueError:  If it cannot find a `nonce_offset` or valid `MZ header`
        """
        eof_shellcode_offsets = []
        nonce_offsets = []

        nonce_offsets = list(iter_nonce_offsets(fh, maxrange=maxrange))
        eof_shellcode_offsets = [
            offset + len(cls.EOF_SHELLCODE_MARKER)
            for offset in iter_find_needle(fh, cls.EOF_SHELLCODE_MARKER, start_offset=0, max_offset=maxrange)
        ]
        logger.debug(f"Found nonce offset candidates: {nonce_offsets}")
        logger.debug(f"Found eof_shellcode offset candidates: {eof_shellcode_offsets}")

        # Try the most common eof_shellcode and nonce offset candidates first
        xf = None
        found_nonce_offset = None
        for offset, count in collections.Counter(eof_shellcode_offsets + nonce_offsets).most_common():
            logger.debug(f"Found common nonce offset: {offset} ({count})")
            found_nonce_offset = offset
            xf = cls(fh, nonce_offset=found_nonce_offset)
            if pe.find_mz_offset(cast(BinaryIO, xf)) is not None:
                xf.seek(0)
                return xf
        raise ValueError(f"MZ header not found for: {fh}")

    @classmethod
    def from_path(cls, path: Union[str, os.PathLike], maxrange: int = 1024) -> "XorEncodedFile":
        """Constructs a XorEncodedFile from path `path`, raises ValueError if file not determined as a XorEncoded Beacon.

        This is more of a convience method as it calls :meth:`XorEncodedFile.from_file` under the hood.

        Args:
            path: path or path-like to xorencoded file
            maxrange: how far into the file should be try to find the `nonce_offset` candidates (default 1024)

        Returns:
            XorEncodedFile instance

        Raises:
            ValueError:  If it cannot find a `nonce_offset` or valid `MZ header`
        """
        fobj = open(path, "rb")
        return cls.from_file(fobj, maxrange=maxrange)

    def read_nonce(self):
        """Return nonce for current file position or 0 if it cannot be read"""
        pos = self.fh.tell()
        try:
            self.fh.seek(-4, io.SEEK_CUR)
            nonce = self.fh.read(4)
        except OSError:
            nonce = b"\x00\x00\x00\x00"
        if pos < self.nonce_offset + 12:
            # Exclude "encoded filesize" as nonce:
            # | nonce | encoded filesize | encoded MZ | encoded .. |
            offset = pos - (self.nonce_offset + 8)
            nonce = self.initial_nonce[offset:] + nonce[4 - offset :]
        return nonce

    def tell(self):
        return self.fh.tell() - (self.nonce_offset + 8)

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            return self.fh.seek(offset + self.nonce_offset + 8, whence)
        return self.fh.seek(offset, whence)

    def read(self, n=-1):
        data = b""
        nonce = self.read_nonce()
        while True:
            chunk = self.fh.read(4)
            if not chunk:
                break
            # log.debug(f"{chunk}, {nonce}")
            data += xor(chunk, nonce)
            nonce = chunk
            if n > 0 and len(data) >= n:
                break
        if n == -1:
            n = None
        return data[:n]


def build_parser():
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
    return parser


@catch_sigpipe
def main():
    """Entrypoint for beacon-xordecode."""

    parser = build_parser()
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level)

    from .pe import (
        find_magic_mz,
        find_magic_pe,
        find_compile_stamps,
        find_stage_prepend_append,
        find_architecture,
    )

    logger.info("Processing file: {!r}".format(args.input))
    fout = args.output.buffer if hasattr(args.output, "buffer") else args.output
    with open(args.input, "rb") as fin:
        if args.nonce_offset is not None:
            fxor = XorEncodedFile(fin, nonce_offset=args.nonce_offset)
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

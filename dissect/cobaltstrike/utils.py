"""
This module contains generic helper functions used by ``dissect.cobaltstrike``.
"""
import io
import os
import re
import sys
import random
import string
import itertools
from functools import partial, wraps

from typing import BinaryIO, Iterator


def xor(data: bytes, key: bytes) -> bytes:
    """XOR data with key"""
    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return bytes(data)


def catch_sigpipe(func):
    """Catches KeyboardInterrupt and BrokenPipeError (OSError 22 on Windows)."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("Aborted!", file=sys.stderr)
            return 1
        except (BrokenPipeError, OSError) as e:
            # Windows raises -> OSError: [Errno 22] Invalid argument
            if type(e) is OSError and e.errno != 22:
                raise
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            return 1

    return wrapper


def unpack(data: bytes, size: int = None, byteorder="little") -> int:
    return int.from_bytes(data[:size], byteorder=byteorder)


def pack(n: int, size: int = None, byteorder="little") -> bytes:
    if size is None:
        size = (n.bit_length() + 7) // 8
    return n.to_bytes(size, byteorder=byteorder)


unpack_be = partial(unpack, byteorder="big")
pack_be = partial(pack, byteorder="big")

u8 = partial(unpack, size=1)
p8 = partial(pack, size=1)

u16 = partial(unpack, size=2)
p16 = partial(pack, size=2)
u16be = partial(unpack, size=2, byteorder="big")
p16be = partial(pack, size=2, byteorder="big")

u32 = partial(unpack, size=4)
p32 = partial(pack, size=4)
u32be = partial(unpack, size=4, byteorder="big")
p32be = partial(pack, size=4, byteorder="big")


def iter_find_needle(
    fp: BinaryIO,
    needle: bytes,
    start_offset: int = None,
    max_offset: int = 0,
) -> Iterator[int]:
    """Return an iterator yielding `offset` for found `needle` bytes in file `fp`.

    Side effects: file handle position due to seeking.

    Args:
        fp: file like object
        needle: needle to search for
        start_offset: offset in file object to start searching from, if None it will search from current position
        max_offset: how far we search for into the file, 0 for no limit

    Yields:
        offset where `needle` was found in file `fp`
    """
    needle_len = len(needle)
    overlap_len = needle_len - 1
    saved = b"\x00" * overlap_len
    if start_offset is not None:
        fp.seek(start_offset)
    while True:
        pos = fp.tell()
        if max_offset and pos > max_offset:
            break
        block = fp.read(io.DEFAULT_BUFFER_SIZE)
        if not block:
            break
        d = saved + block
        p = -1
        while True:
            p = d.find(needle, p + 1)
            if p == -1 or max_offset and p > max_offset:
                break
            offset = pos + p - overlap_len
            yield offset
        saved = d[-overlap_len:]


def checksum8(text: str) -> int:
    """Compute the *checksum8* value of text"""
    if len(text) < 4:
        return 0
    text = text.replace("/", "")
    return sum(map(ord, text)) % 256


def is_stager_x86(uri: str) -> bool:
    """Return ``True`` if URI is a x86 stager URI, otherwise ``False``"""
    return checksum8(uri) == 92


def is_stager_x64(uri: str) -> bool:
    """Return ``True`` if URI is a x64 stager URI, otherwise ``False``"""
    return bool(checksum8(uri) == 93 and re.match("^/[A-Za-z0-9]{4}$", uri))


def random_stager_uri(*, x64: bool = False, length: int = 4) -> str:
    """Generate a random (valid *checksum8*) stager URI. Defaults to x86 URIs unless `x64` is ``True``.

    Args:
        x64: generate a x64 stager URI if ``True``, ``False`` for a x86 stager URI. (default: ``False``)
        length: length of URI to generate, exluding the "/" prefix. (default: 4)

    Returns:
        random stager URI
    """
    if x64 and length != 4:
        raise ValueError("length must be exactly 4 for x64 stager uris")
    if length < 3:
        raise ValueError("length must be at least 3 chars")
    is_stager = is_stager_x64 if x64 else is_stager_x86
    chars = string.ascii_letters + string.digits
    while True:
        uri = "/" + "".join(
            itertools.islice(
                iter(partial(random.choice, chars), None),
                length,
            )
        )
        if is_stager(uri):
            return uri

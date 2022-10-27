"""
This module contains generic helper functions used by ``dissect.cobaltstrike``.
"""
import io
import os
import re
import sys
import errno
import random
import string
import reprlib
from collections import OrderedDict
from functools import partial, wraps
from contextlib import contextmanager

from typing import BinaryIO, Iterator, NamedTuple


def xor(data: bytes, key: bytes) -> bytes:
    """XOR data with key"""
    if sum(key) == 0:
        return data
    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return bytes(data)


def netbios_encode(data: bytes, offset: int = 0x41) -> bytes:
    """Encode `data` using NetBIOS encoding and return the encoded bytes.

    Args:
        data: bytes to be NetBIOS encoded
        offset: offset used for encoding, defaults to char ``A`` (``0x41``)

    Returns:
        NetBIOS encoded bytes
    """
    barray = []
    for c in bytearray(data):
        a = ((c & 0xF0) >> 4) + offset
        b = (c & 0x0F) + offset
        barray.append(a)
        barray.append(b)
    return bytes(barray)


def netbios_decode(data: bytes, offset: int = 0x41) -> bytes:
    """Decode the netbios encoded `data` and return the decoded bytes.

    Args:
        data: bytes to be NetBIOS decoded
        offset: offset used for decoding, defaults to char ``A`` (``0x41``)

    Returns:
        NetBIOS decoded bytes
    """
    barray = []
    for i in range(0, len(data), 2):
        a = (data[i] - offset) << 4
        b = data[i + 1] - offset
        barray.append(a + b)
    return bytes(barray)


@contextmanager
def retain_file_offset(fobj, offset=None, whence=io.SEEK_SET):
    """Return a context manager that changes the position of the file-like object `fobj` to the given byte `offset`.
    After completion of the block it restores the original position of the file.

    Args:
        fobj: file-like object
        offset: offset to seek to relative to position indicated by `whence`. If ``None`` no seek will be done.
        whence: default is ``SEEK_SET``, values for `whence` are:

            - ``SEEK_SET`` or ``0`` – start of the stream (the default); offset should be zero or positive
            - ``SEEK_CUR`` or ``1`` – current stream position; offset may be negative
            - ``SEEK_END`` or ``2`` – end of the stream; offset is usually negative

    Returns:
        context manager
    """
    try:
        pos = fobj.tell()
        if offset is not None:
            fobj.seek(offset, whence)
        yield fobj
    finally:
        fobj.seek(pos)


def catch_sigpipe(func):
    """Decorator for catching KeyboardInterrupt and BrokenPipeError (OSError 22 on Windows)."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("Aborted!", file=sys.stderr)
            return 1
        except OSError as e:
            # Only catch:
            #  - BrokenPipeError: [Errno 32] Broken pipe
            #  - OSError: [Errno 22] Invalid argument
            if e.errno in (errno.EPIPE, errno.EINVAL):
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return 1
            # Raise other OSError exceptions
            raise

    return wrapper


def unpack(data: bytes, size: int = None, byteorder="little", signed=False) -> int:
    return int.from_bytes(data[:size], byteorder=byteorder, signed=signed)


def pack(n: int, size: int = None, byteorder="little", signed=False) -> bytes:
    if size is None:
        size = (n.bit_length() + 7) // 8
    return n.to_bytes(size, byteorder=byteorder, signed=signed)


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

u64 = partial(unpack, size=8)
p64 = partial(pack, size=8)
u64be = partial(unpack, size=8, byteorder="big")
p64be = partial(pack, size=8, byteorder="big")


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
        uri = "/" + "".join(random.choice(chars) for _ in range(length))
        if is_stager(uri):
            return uri


def namedtuple_reprlib_repr(nt: NamedTuple) -> str:
    """Return a `reprlib` version of __repr__ for namedtuple `nt`"""
    return "{name}({fields})".format(
        name=nt.__class__.__name__,
        fields=", ".join(f"{field}=" + reprlib.repr(getattr(nt, field)) for field in nt._fields),
    )


def enable_reprlib_cstruct():
    """Enable `reprlib` style __repr__ for `dissect.cstruct` instances."""
    from dissect.cstruct.types.instance import Instance

    def reprlib_repr(self) -> str:
        values = ", ".join(f"{k}={hex(v) if isinstance(v, int) else reprlib.repr(v)}" for k, v in self._values.items())
        return f"<{self._type.name} {values}>"

    Instance.__repr__ = reprlib_repr


def enable_reprlib_flow_record():
    """Enable `reprlib` style __repr__ for `flow.record` instances."""
    from flow.record import Record

    def reprlib_repr(self) -> str:
        return "<{} {}>".format(
            self._desc.name, " ".join("{}={}".format(k, reprlib.repr(getattr(self, k))) for k in self._desc.fields)
        )

    Record.__repr__ = reprlib_repr


class LRUDict(OrderedDict):
    "Limit size, evicting the least recently looked-up key when full"

    def __init__(self, maxsize=128, *args, **kwds):
        self.maxsize = maxsize
        super().__init__(*args, **kwds)

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self.maxsize:
            oldest = next(iter(self))
            del self[oldest]

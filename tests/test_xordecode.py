import io
import hashlib

from dissect.cobaltstrike import pe
from dissect.cobaltstrike import utils
from dissect.cobaltstrike import xordecode

import pytest


def test_xordecode(beacon_x86_file):
    with pytest.raises(ValueError, match="MZ header not found for: .*"):
        xf = xordecode.XorEncodedFile.from_file(beacon_x86_file, maxrange=10)

    xf = xordecode.XorEncodedFile.from_file(beacon_x86_file)

    assert "XorEncodedFile" in repr(xf)
    assert xf.read(12) == b"\x90\x90\x90\x90\x90\x90\x90\x90MZRE"

    xf.seek(9)
    assert xf.read(3) == b"ZRE"

    xf.seek(-100, whence=io.SEEK_END)
    assert len(xf.read(1000)) == 100

    xf.seek(0)
    md5 = hashlib.md5()
    size = 0
    while True:
        data = xf.read(io.DEFAULT_BUFFER_SIZE)
        if not data:
            break
        md5.update(data)
        size += len(data)
    assert md5.hexdigest() == "9909e7f117ef993fce1042707f56fced"

    xf.seek(0)
    data = xf.read()
    md5 = hashlib.md5(data)
    assert md5.hexdigest() == "9909e7f117ef993fce1042707f56fced"
    assert len(data) == size

    xf.seek(0, whence=io.SEEK_END)
    assert xf.tell() == size

    assert pe.find_compile_stamps(xf) == (1606126059, 1604366849)


def test_from_file(tmp_path):
    with pytest.raises(ValueError, match="MZ header not found for: .*"):
        xordecode.XorEncodedFile.from_file(io.BytesIO(b"testing"))

    xf = xordecode.XorEncodedFile(io.BytesIO(b"\x00\x00\x00\x00SSSStest"))
    assert xf.read() == b"test"

    xf = xordecode.XorEncodedFile(io.BytesIO(b"\x01\x02\x03\x04SSSStestABCD"))
    assert xf.read() == utils.xor(b"test", b"\x01\x02\x03\x04") + utils.xor(b"test", b"ABCD")

    p = tmp_path / "small"
    p.write_bytes(b"foo")
    with p.open("rb") as f:
        xf = xordecode.XorEncodedFile(f)
        assert xf.read() == b""

import pytest
from dissect.cobaltstrike import utils


def test_packing():
    assert utils.p32(0x41424344) == b"DCBA"
    assert utils.u32(b"DCBA") == 0x41424344

    assert utils.p32be(0x41424344) == b"ABCD"
    assert utils.u32be(b"ABCD") == 0x41424344

    assert utils.p16(0x4142) == b"BA"
    assert utils.p16be(0x4142) == b"AB"

    assert utils.p8(0x41) == b"A"
    assert utils.u8(b"A") == 0x41

    assert utils.p64(0x800) == b"\x00\x08\x00\x00\x00\x00\x00\x00"
    assert utils.u64(b"\x00\x08\x00\x00\x00\x00\x00\x00") == 0x800

    assert utils.p64be(12345) == b"\x00\x00\x00\x00\x00\x0009"
    assert utils.u64be(b"\x00\x00\x00\x00\x00\x0009") == 12345

    assert utils.unpack(b"ABCDEFGHIJ") == 0x4A494847464544434241
    assert utils.unpack_be(b"ABCDEFGHIJ") == 0x4142434445464748494A

    assert utils.pack(0x4A494847464544434241) == b"ABCDEFGHIJ"
    assert utils.pack_be(0x4142434445464748494A) == b"ABCDEFGHIJ"

    assert utils.u8(b"12345") == 0x31


def test_xor():
    assert utils.xor(b"hello", b"world") == b"\x1f\n\x1e\x00\x0b"
    assert utils.xor(b"goodbye", b"\x01") == b"fnnecxd"
    assert utils.xor(b"\x11\x22\x33\x44", b"\x11\x22\x33\x44") == b"\x00\x00\x00\x00"
    assert utils.xor(b"\x11\x11\x11\x11", b"\x11") == b"\x00\x00\x00\x00"
    assert utils.xor(b"hi", b"secret") == b"\x1b\x0c"
    assert utils.xor(b"no xor key", b"") == b"no xor key"
    assert utils.xor(b"zero xor key", b"\x00\x00\x00\x00") == b"zero xor key"


@pytest.mark.parametrize(
    ("uri", "expected", "x86", "x64"),
    [
        ("/TOKn", 92, True, False),
        ("/TO/Kn", 92, True, False),
        ("/H7mp", 92, True, False),
        ("/oOo0", 93, False, True),
        ("/oO/o0", 93, False, False),
        ("undisappointing", 92, True, False),
        ("/pendants", 93, False, False),
        ("/toy", 92, True, False),
        ("/spy", 92, True, False),
        ("releasenotes.txt", 152, False, False),
    ],
)
def test_checksum8(uri, expected, x86, x64):
    assert utils.checksum8(uri) == expected
    assert utils.is_stager_x86(uri) == x86
    assert utils.is_stager_x64(uri) == x64


def test_random_stager_uri():
    assert utils.is_stager_x86(utils.random_stager_uri())
    assert utils.is_stager_x64(utils.random_stager_uri(x64=True))

    assert utils.is_stager_x86(utils.random_stager_uri(length=100))
    assert utils.is_stager_x64(utils.random_stager_uri(x64=True))

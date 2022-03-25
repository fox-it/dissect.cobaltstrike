from dissect.cobaltstrike import pe
from dissect.cobaltstrike import beacon
from dissect.cobaltstrike import xordecode


def test_pe_beacon_x64(beacon_x64_file):
    xf = xordecode.XorEncodedFile.from_file(beacon_x64_file)
    assert xf
    assert pe.find_architecture(xf) == "x64"
    assert pe.find_magic_mz(xf) == b"MZAR"
    assert pe.find_magic_pe(xf) == b"PE"

    prepend, append = pe.find_stage_prepend_append(xf)
    assert append is None
    assert prepend == b"\x90\x90\x90\x90\x90\x90\x90\x90"
    xf.seek(0)
    assert xf.read(100).startswith(prepend + pe.find_magic_mz(xf))


def test_pe_beacon_x86(beacon_x86_file):
    xf = xordecode.XorEncodedFile.from_file(beacon_x86_file)
    assert pe.find_architecture(xf) == "x86"
    assert pe.find_magic_mz(xf) == b"MZRE"
    assert pe.find_magic_pe(xf) == b"PE"
    assert pe.find_compile_stamps(xf) == (1606126059, 1604366849)

    prepend, append = pe.find_stage_prepend_append(xf)
    assert prepend == b"\x90\x90\x90\x90\x90\x90\x90\x90"
    assert append is None


def test_pe_stage_append(beacon_custom_xorkey_file):
    xf = xordecode.XorEncodedFile.from_file(beacon_custom_xorkey_file)
    prepend, append = pe.find_stage_prepend_append(xf)
    assert prepend == b"\x90\x90\x90"
    assert append == b"\x90\x90\x90"
    assert pe.find_architecture(xf) == "x86"
    assert pe.find_magic_mz(xf) == b"MZRE"
    assert pe.find_magic_pe(xf) == b"De"
    assert pe.find_compile_stamps(xf) == (1636928082, 1627994693)
    assert beacon.BeaconVersion.from_pe_export_stamp(1627994693).version == "Cobalt Strike 4.4 (Aug 04, 2021)"

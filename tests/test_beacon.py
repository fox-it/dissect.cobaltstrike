import io
import sys
import subprocess
from unittest.mock import patch

from dissect.cobaltstrike import beacon

import pytest


def test_beacon_from_file(beacon_x64_file):
    bconfig = beacon.BeaconConfig.from_file(beacon_x64_file)
    assert len(bconfig.domains)
    assert bconfig.xorencoded
    assert bconfig.xorkey == b"\x2e"
    assert bconfig.architecture == "x64"
    assert bconfig.pe_compile_stamp == 1628256615
    assert bconfig.pe_export_stamp == 1614696183
    assert "<BeaconConfig" in repr(bconfig)
    assert bconfig.watermark == 0
    assert bconfig.version == "Cobalt Strike 4.3 (Mar 03, 2021)"
    assert bconfig.max_setting_enum == 70
    assert max(bconfig.setting_enums) == 70

    with pytest.raises(ValueError, match="No valid Beacon configuration found"):
        beacon.BeaconConfig.from_file(io.BytesIO(b"no bacon for you"))


def test_beacon_from_path(beacon_x86_file, tmp_path):
    with (tmp_path / "beacon_x86.bin") as p:
        p.write_bytes(beacon_x86_file.read())
        bconfig = beacon.BeaconConfig.from_path(p)
        assert len(bconfig.domains)
        assert len(bconfig.uris)
        assert bconfig.xorencoded
        assert bconfig.protocol == "https"

    with (tmp_path / "bacon.bin") as p:
        p.write_bytes(b"no bacon for you")
        with pytest.raises(ValueError, match="No valid Beacon configuration found"):
            beacon.BeaconConfig.from_path(p)


def test_beacon_from_bytes(beacon_x86_file):
    data = beacon_x86_file.read()
    bconfig = beacon.BeaconConfig.from_bytes(data)
    assert len(bconfig.domains)
    assert bconfig.xorencoded
    assert bconfig.architecture == "x86"
    assert bconfig.watermark == 0x5109BF6D
    assert bconfig.pe_export_stamp == 0x5FA0B201
    assert bconfig.version == "Cobalt Strike 4.2 (Nov 06, 2020)"
    assert bconfig.max_setting_enum == 58

    with pytest.raises(ValueError, match="No valid Beacon configuration found"):
        beacon.BeaconConfig.from_bytes(b"no bacon for you")


def test_beacon_custom_xorkey(beacon_custom_xorkey_file):
    # Read the beacon into memory to speed things up
    fh = io.BytesIO(beacon_custom_xorkey_file.read())

    # Try default xor keys.
    with pytest.raises(ValueError, match="No valid Beacon configuration found"):
        beacon.BeaconConfig.from_file(fh)

    # Try all xorkeys (but with invalid one)
    with patch("dissect.cobaltstrike.beacon.make_byte_list", return_value=[b"\xaa"]):
        with pytest.raises(ValueError, match="No valid Beacon configuration found"):
            bconfig = beacon.BeaconConfig.from_file(fh, all_xor_keys=True)

    # Make the correct XOR key the first entry
    org_make_byte_list = beacon.make_byte_list

    def patched(exclude=()):
        org_result = org_make_byte_list(exclude)
        return [b"\xcc"] + org_result

    # Try all xorkeys (mocked to try the correct XOR key first)
    with patch("dissect.cobaltstrike.beacon.make_byte_list", new=patched):
        bconfig = beacon.BeaconConfig.from_file(fh, all_xor_keys=True)
        assert len(bconfig.domains)
        assert bconfig.xorkey == b"\xcc"


def test_deprecated_setting():
    watermark_hash_data = b"\x00$\x00\x03\x00 AAECAwQFBgcICQoLDA0ODw==\x00\x00\x00\x00\x00\x00\x00\x00"
    inject_options_data = b"\x00$\x00\x01\x00\x02\x00\x03"
    beacon1 = beacon.BeaconConfig(watermark_hash_data)
    beacon2 = beacon.BeaconConfig(inject_options_data)

    SETTING_INJECT_OPTIONS = beacon.DeprecatedBeaconSetting.SETTING_INJECT_OPTIONS
    SETTING_WATERMARKHASH = beacon.BeaconSetting.SETTING_WATERMARKHASH

    assert SETTING_WATERMARKHASH.value == SETTING_INJECT_OPTIONS.value == 36

    assert beacon1.raw_settings[SETTING_WATERMARKHASH.name]
    assert beacon1.settings_by_index[36] == b"AAECAwQFBgcICQoLDA0ODw=="
    with pytest.raises(KeyError):
        assert beacon1.raw_settings[SETTING_INJECT_OPTIONS.name]

    assert beacon2.raw_settings[SETTING_INJECT_OPTIONS.name] == 3
    assert beacon2.settings_by_index[36] == 3
    with pytest.raises(KeyError):
        assert beacon2.raw_settings[SETTING_WATERMARKHASH.name]


def test_setting_useragent_edgecase():
    """
    Test edgecase where length of useragent is > 0x80 but SETTING size is 0x80.

    The handling is done in ``iter_settings()``.
    """
    data = """
    00 09 00 03 00 80 4d 6f  7a 69 6c 6c 61 2f 34 2e
    30 20 28 63 6f 6d 70 61  74 69 62 6c 65 3b 20 4d
    53 49 45 20 37 2e 30 3b  20 57 69 6e 64 6f 77 73
    20 4e 54 20 31 30 2e 30  3b 20 57 69 6e 36 34 3b
    20 78 36 34 3b 20 54 72  69 64 65 6e 74 2f 37 2e
    30 3b 20 2e 4e 45 54 34  2e 30 43 3b 20 2e 4e 45
    54 34 2e 30 45 3b 20 2e  4e 45 54 20 43 4c 52 20
    32 2e 30 2e 35 30 37 32  37 3b 20 2e 4e 45 54 20
    43 4c 52 20 33 2e 30 2e  33 30 37 32 39 3b 20 2e
    4e 45 54 20 43 4c 52 20  33 2e 35 2e 33 30 37 32
    39 29

    00 0a 00 03 00 40 2f 73  65 61 72 63 68 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00
    """.replace(
        "\n", ""
    )
    config = beacon.BeaconConfig(bytes.fromhex(data))

    ua = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)"  # noqa: 501
    assert config.settings["SETTING_USERAGENT"] == ua
    assert config.settings["SETTING_SUBMITURI"] == "/search"


def test_beacon_settings(beacon_x86_file):
    bconfig = beacon.BeaconConfig.from_file(beacon_x86_file)

    # fmt: off
    assert bconfig.setting_enums == [
        1, 2, 3, 4, 5, 7, 8, 14, 29, 30, 31, 26, 27, 28, 37, 38, 39, 9, 10, 11, 12, 13,
        54, 50, 35, 58, 57, 55, 40, 41, 42, 43, 44, 45, 46, 47, 53, 51, 52,
    ]
    # fmt: on

    assert bconfig.max_setting_enum == 58

    assert bconfig.settings["SETTING_DOMAINS"] == "londonteea.com,/favicon.css"

    domain_enum = beacon.BeaconSetting.SETTING_DOMAINS
    assert bconfig.settings_by_index[domain_enum.value] == "londonteea.com,/favicon.css"

    assert bconfig.raw_settings[domain_enum.name] == b"londonteea.com,/favicon.css".ljust(256, b"\x00")
    assert bconfig.raw_settings["SETTING_DOMAINS"] == b"londonteea.com,/favicon.css".ljust(256, b"\x00")
    assert bconfig.raw_settings_by_index[domain_enum.value] == b"londonteea.com,/favicon.css".ljust(256, b"\x00")

    d = bconfig.settings_map("enum", pretty=False, parse=False)
    assert d[beacon.BeaconSetting.SETTING_PORT] == b"\x01\xbb"
    d = bconfig.settings_map("enum", pretty=False, parse=True)
    assert d[beacon.BeaconSetting.SETTING_PORT] == 443

    d = bconfig.settings_map("enum", pretty=False)
    assert d[beacon.BeaconSetting.SETTING_DOMAINS] == b"londonteea.com,/favicon.css".ljust(256, b"\x00")
    d = bconfig.settings_map("enum", pretty=True)
    assert d[beacon.BeaconSetting.SETTING_DOMAINS] == "londonteea.com,/favicon.css"


def test_beacon_settings_readonly(beacon_x64_file):
    bconfig = beacon.BeaconConfig.from_file(beacon_x64_file)
    with pytest.raises(TypeError):
        bconfig.settings["SETTING_DOMAINS"] = "test"

    with pytest.raises(TypeError):
        bconfig.raw_settings["foo"] = "bar"


@pytest.mark.parametrize(
    ("fixture", "options", "ret", "stdout", "stderr"),
    [
        pytest.param(
            "beacon_custom_xorkey_file",
            ["-x", "0xCC"],
            0,
            b"SETTING_PUBKEY = '36aff0b273cb7aa704e4219ad3be78defcc8c1d7ecb779d55f438e82c7138673'",
            None,
            id="beacon_custom_xorkey_file-stdin-0xcc",
        ),
        pytest.param(
            "beacon_x86_file",
            [],
            0,
            b"SETTING_PUBKEY = '71fab2149cbdce552f00e6d75372494d3f7755d366fd6849a6d5c9e0f73bc40f'",
            None,
            id="beacon_x86_file-stdin-normal",
        ),
        pytest.param(
            "beacon_x86_file",
            ["-t", "c2profile"],
            0,
            b'prepend "wordpress_ed1f617bbd6c004cc09e046f3c1b7148="',
            None,
            id="beacon_x86_file-stdin-c2profile",
        ),
        pytest.param(
            "beacon_x86_file",
            ["-t", "raw"],
            0,
            b"<Setting index=<BeaconSetting.SETTING_WATERMARK: 37>, type=<SettingsType.TYPE_INT: 2>",
            None,
            id="beacon_x86_file-stdin-raw",
        ),
        pytest.param(
            "beacon_x86_file",
            ["-t", "dumpstruct"],
            0,
            b"BeaconSetting.SETTING_PUBKEY",
            None,
            id="beacon_x86_file-stdin-dumpstruct",
        ),
        pytest.param(
            "beacon_x64_path",
            ["-t", "normal"],
            0,
            b"SETTING_PUBKEY = ",
            None,
            id="beacon_x64_path-normal",
        ),
        pytest.param(
            "beacon_x64_config_block",
            [],
            0,
            b"SETTING_PUBKEY = ",
            None,
            id="beacon_x64_config_block-stdin-unobfuscated",
        ),
        pytest.param(
            b"NO BACON",
            [],
            1,
            None,
            b"No beacon configuration found",
            id="invalid-beacon-stdin",
        ),
    ],
)
def test_main(capfdbinary, request, fixture, options, ret, stdout, stderr):
    if isinstance(fixture, bytes):
        beacon_file = io.BytesIO(fixture)
    else:
        beacon_file = request.getfixturevalue(fixture)

    if isinstance(beacon_file, bytes):
        beacon_file = io.BytesIO(beacon_file)

    stdin = subprocess.PIPE if hasattr(beacon_file, "read") else None
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "dissect.cobaltstrike.beacon",
            *options,
            "-" if stdin else beacon_file,
        ],
        stdin=stdin,
    )
    if stdin:
        while True:
            data = beacon_file.read(1024)
            if not data:
                break
            proc.stdin.write(data)
            proc.stdin.flush()
        proc.stdin.close()
    proc.wait()
    assert proc.returncode == ret
    cap = capfdbinary.readouterr()
    if stdout:
        assert stdout in cap.out
    if stderr:
        assert stderr in cap.err

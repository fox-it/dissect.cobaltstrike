import io
import zipfile
from pathlib import Path

import pytest

from dissect.cobaltstrike import beacon

beacons = {
    # x86 beacon
    "beacon_x86": "4f571c0bc97c20eefc58fa3faf32148d.bin.zip",
    # x64 beacon
    "beacon_x64": "1897a6cdf17271807bd6ec7c60fffea3.bin.zip",
    # x86 beacon, custom xor key, stage prepend and append, custom PE
    "beacon_custom_xorkey": "3fdf92571d10485b05904e35c635c655.bin.zip",
    # dns beacon, custom xor key 0xaf, CS v4.3
    "dns_beacon": "a1573fe60c863ed40fffe54d377b393a.bin.zip",
    # c2test beacon, beacon used in test_c2.py
    "c2test_beacon": "37882262c9b5e971067fd989b26afe28.bin.zip",
    # beacon with unicode in domain
    "punycode_beacon": "5a197a8bb628a2555f5a86c51b85abd7.bin.zip",
}


# This automatically generates a fixture for each beacon file
def generate_beacon_file_fixture(filename):
    @pytest.fixture()
    def my_fixture(request):
        testpath = Path(request.fspath.dirname)
        beacon_zip_path = testpath / "beacons" / filename
        if not beacon_zip_path.exists():
            pytest.skip(f"Beacon {beacon_zip_path!r} not found")

        # Extract the beacon file from the zip archive
        with zipfile.ZipFile(beacon_zip_path) as zf:
            data = zf.read(beacon_zip_path.stem, pwd=b"dissect.cobaltstrike")

        # Return the beacon file as a BytesIO object
        with io.BytesIO(data) as fh:
            yield fh

    return my_fixture


def generate_beacon_path_fixture(filename):
    @pytest.fixture()
    def my_fixture(request, tmp_path):
        testpath = Path(request.fspath.dirname)
        beacon_zip_path = testpath / "beacons" / filename
        if not beacon_zip_path.exists():
            pytest.skip(f"Beacon {beacon_zip_path!r} not found")

        with zipfile.ZipFile(beacon_zip_path) as zf:
            zf.extract(beacon_zip_path.stem, path=tmp_path, pwd=b"dissect.cobaltstrike")
        return tmp_path / beacon_zip_path.stem

    return my_fixture


def generate_beacon_bconfig_fixture(name):
    @pytest.fixture()
    def my_fixture(request):
        path_fixture = request.getfixturevalue(f"{name}_path")
        return beacon.BeaconConfig.from_path(path_fixture, xor_keys=[b"\x69", b"\x2e", b"\xaf", b"\xcc"])

    return my_fixture


def inject_beacon_file_fixture(name, filename):
    globals()[f"{name}_file"] = generate_beacon_file_fixture(filename)


def inject_beacon_path_fixture(name, filename):
    globals()[f"{name}_path"] = generate_beacon_path_fixture(filename)


def inject_beacon_bconfig_fixture(name):
    globals()[f"{name}_bconfig"] = generate_beacon_bconfig_fixture(name)


for name, filename in beacons.items():
    inject_beacon_file_fixture(name, filename)
    inject_beacon_path_fixture(name, filename)
    inject_beacon_bconfig_fixture(name)


@pytest.fixture()
def beacon_x64_config_block(beacon_x64_file):
    return beacon.BeaconConfig.from_file(beacon_x64_file).config_block

import io
import zipfile
from contextlib import contextmanager
from pathlib import Path

from dissect.cobaltstrike import beacon

import pytest

beacons = {
    # x86 beacon
    "beacon_x86": "4f571c0bc97c20eefc58fa3faf32148d.bin.zip",
    # x64 beacon
    "beacon_x64": "1897a6cdf17271807bd6ec7c60fffea3.bin.zip",
    # x86 beacon, custom xor key, stage prepend and append, custom PE
    "beacon_custom_xorkey": "3fdf92571d10485b05904e35c635c655.bin.zip",
    # dns beacon, custom xor key 0xaf, CS v4.3
    "dns_beacon": "a1573fe60c863ed40fffe54d377b393a.bin.zip",
}


# This automatically generates a fixture for each beacon file
def generate_beacon_file_fixture(filename):
    @pytest.fixture()
    def my_fixture(request):
        testpath = Path(request.fspath.dirname)
        beacon_zip_path = testpath / "beacons" / filename
        if not beacon_zip_path.exists():
            pytest.skip(f"Beacon {beacon_zip_path!r} not found")
        with unzip_beacon_as_fh(beacon_zip_path) as beacon_file:
            # ZipExtFile.seek() raises io.UnsupportedOperation on Python 3.6
            try:
                beacon_file.seek(0)
                yield beacon_file
            except io.UnsupportedOperation:
                # fallback to BytesIO
                with io.BytesIO(beacon_file.read()) as fh:
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


def inject_beacon_file_fixture(name, filename):
    globals()[name] = generate_beacon_file_fixture(filename)


def inject_beacon_path_fixture(name, filename):
    globals()[name] = generate_beacon_path_fixture(filename)


for name, filename in beacons.items():
    inject_beacon_file_fixture(f"{name}_file", filename)
    inject_beacon_path_fixture(f"{name}_path", filename)


@contextmanager
def unzip_beacon_as_fh(zip_file, pwd=b"dissect.cobaltstrike"):
    """Return file object of beacon from zipfile"""
    with zipfile.ZipFile(zip_file) as zf:
        yield zf.open(zip_file.stem, pwd=pwd)


@pytest.fixture()
def beacon_x64_config_block(beacon_x64_file):
    return beacon.BeaconConfig.from_file(beacon_x64_file).config_block

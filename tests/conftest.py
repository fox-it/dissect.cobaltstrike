import io
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

beacons = {
    # x86 beacon
    "beacon_x86": "4f571c0bc97c20eefc58fa3faf32148d.bin.zip",
    # x64 beacon
    "beacon_x64": "1897a6cdf17271807bd6ec7c60fffea3.bin.zip",
    # x86 beacon, custom xor key, stage prepend and append, custom PE
    "beacon_custom_xorkey": "3fdf92571d10485b05904e35c635c655.bin.zip",
}


# This automatically generates a fixture for each beacon file
def generate_beacon_file_fixture(filename):
    @pytest.fixture(scope="function")
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


def inject_beacon_file_fixture(name, filename):
    globals()[name] = generate_beacon_file_fixture(filename)


for name, filename in beacons.items():
    inject_beacon_file_fixture(f"{name}_file", filename)


@contextmanager
def unzip_beacon_as_fh(zip_file, pwd=b"dissect.cobaltstrike"):
    """Return file object of beacon from zipfile"""
    with zipfile.ZipFile(zip_file) as zf:
        yield zf.open(zip_file.stem, pwd=pwd)

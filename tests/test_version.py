import datetime

from dissect.cobaltstrike import version


def test_pe_export_date_strings():
    # verify dates in PE_EXPORT_STAMP_TO_VERSION
    dates = [version.BeaconVersion(x).date for x in version.PE_EXPORT_STAMP_TO_VERSION.values()]
    for date, version_str in zip(dates, version.PE_EXPORT_STAMP_TO_VERSION.values()):
        date_str = date.strftime("%b %d, %Y")
        assert date_str in version_str

    # verify dates in MAX_ENUM_TO_VERSION
    dates = [version.BeaconVersion(x).date for x in version.MAX_ENUM_TO_VERSION.values()]
    for date, version_str in zip(dates, version.MAX_ENUM_TO_VERSION.values()):
        date_str = date.strftime("%b %d, %Y")
        assert date_str in version_str


def test_beacon_versions():
    ver = version.BeaconVersion.from_max_setting_enum(73)
    assert str(ver) == "Cobalt Strike 4.5 (Dec 14, 2021)"
    assert str(ver) == ver.version
    assert repr(ver) == "<BeaconVersion 'Cobalt Strike 4.5 (Dec 14, 2021)', tuple=(4, 5), date=2021-12-14>"
    assert ver.tuple == (4, 5)
    assert ver.date == datetime.date(2021, 12, 14)
    assert ver.version_only == "4.5"
    assert ver.version_string == "Cobalt Strike 4.5"

    ver = version.BeaconVersion.from_max_setting_enum(0)
    assert repr(ver) == "<BeaconVersion 'Unknown', tuple=None, date=None>"
    assert ver.version == "Unknown"
    assert ver.tuple is None
    assert ver.date is None
    assert ver.version_only == "Unknown"
    assert ver.version_string == "Cobalt Strike Unknown"

    ver = version.BeaconVersion.from_pe_export_stamp(0)
    assert repr(ver) == "<BeaconVersion 'Unknown', tuple=None, date=None>"
    assert ver.version == "Unknown"
    assert ver.tuple is None
    assert ver.date is None

    ver = version.BeaconVersion.from_pe_export_stamp(0x579A6849)
    assert ver.version == "Cobalt Strike 3.4 (Jul 29, 2016)"
    assert ver.tuple == (3, 4)
    assert ver.date == datetime.date(2016, 7, 29)

    a = version.BeaconVersion("Cobalt Strike 4.5 (Dec 14, 2021)")
    b = version.BeaconVersion("Cobalt Strike 4.5 (Dec 14, 2021)")
    assert a == b
    assert hash(a) == hash(b)

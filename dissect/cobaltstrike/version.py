"""
This module contains the :class:`BeaconVersion` class and mappings for determining the
Cobalt Strike version of beacon payloads.

.. note::
    Deducing the Cobalt Strike version using :meth:`BeaconVersion.from_pe_export_stamp`
    is more accurate than :meth:`BeaconVersion.from_max_setting_enum`. However, if the
    `pe_export_stamp` is not known, deducing from `max_setting_enum` is still a good
    version estimate.
"""

import re
import datetime

from typing import Dict, Tuple, Optional

MAX_ENUM_TO_VERSION: Dict[int, str] = {
    20: "Cobalt Strike 3.4 (Jul 29, 2016)",
    31: "Cobalt Strike 3.6 (Dec 08, 2016)",
    35: "Cobalt Strike 3.7 (Mar 15, 2017)",
    36: "Cobalt Strike 3.8 (May 23, 2017)",
    37: "Cobalt Strike 3.9 (Sep 26, 2017)",
    38: "Cobalt Strike 3.11 (Apr 09, 2018)",
    39: "Cobalt Strike 3.11 (May 24, 2018)",
    48: "Cobalt Strike 3.12 (Sep 06, 2018)",
    49: "Cobalt Strike 3.13 (Jan 02, 2019)",
    53: "Cobalt Strike 3.14 (May 04, 2019)",
    55: "Cobalt Strike 4.0 (Dec 05, 2019)",
    58: "Cobalt Strike 4.1 (Jun 25, 2020)",
    59: "Cobalt Strike 4.2 (Nov 06, 2020)",
    70: "Cobalt Strike 4.3 (Mar 03, 2021)",
    73: "Cobalt Strike 4.5 (Dec 14, 2021)",
    74: "Cobalt Strike 4.7 (Aug 17, 2022)",
}
""" Max setting enum to Cobalt Strike version mapping """

PE_EXPORT_STAMP_TO_VERSION: Dict[int, str] = {
    0x579A6849: "Cobalt Strike 3.4 (Jul 29, 2016)",
    0x57DCA5FC: "Cobalt Strike 3.5 (Sep 22, 2016)",
    0x58487E41: "Cobalt Strike 3.6 (Dec 08, 2016)",
    0x58BCA7CA: "Cobalt Strike 3.7 (Mar 15, 2017)",
    0x5923564D: "Cobalt Strike 3.8 (May 23, 2017)",
    0x59BE846A: "Cobalt Strike 3.9 (Sep 26, 2017)",
    0x5A29B49D: "Cobalt Strike 3.10 (Dec 11, 2017)",
    0x5AC92EA9: "Cobalt Strike 3.11 (Apr 09, 2018)",
    0x5B048335: "Cobalt Strike 3.11 (May 24, 2018)",
    0x5B90504C: "Cobalt Strike 3.12 (Sep 06, 2018)",
    0x5C26A9C6: "Cobalt Strike 3.13 (Jan 02, 2019)",
    0x5CB90DF5: "Cobalt Strike 3.14 (May 02, 2019)",
    0x5CCCC811: "Cobalt Strike 3.14 (May 04, 2019)",
    0x5D89B903: "Cobalt Strike 4.0 (Dec 05, 2019)",
    0x5DE82DE4: "Cobalt Strike 4.0 (Dec 05, 2019)",
    0x5DE8F170: "Cobalt Strike 4.0 (Dec 05, 2019)",
    0x5DE8F1FA: "Cobalt Strike 4.0 (Dec 05, 2019)",
    0x5EF2555B: "Cobalt Strike 4.1 (Jun 25, 2020)",
    0x5EF25593: "Cobalt Strike 4.1 (Jun 25, 2020)",
    0x5F94C216: "Cobalt Strike 4.2 (Nov 06, 2020)",
    0x5FA0B201: "Cobalt Strike 4.2 (Nov 06, 2020)",
    0x5FA0B264: "Cobalt Strike 4.2 (Nov 06, 2020)",
    0x603E2D9D: "Cobalt Strike 4.3 (Mar 03, 2021)",
    0x603E4EF7: "Cobalt Strike 4.3 (Mar 03, 2021)",
    0x603F9D1D: "Cobalt Strike 4.3 (Mar 03, 2021)",
    0x61093A45: "Cobalt Strike 4.4 (Aug 04, 2021)",
    0x61093A9E: "Cobalt Strike 4.4 (Aug 04, 2021)",
    0x619D3A1B: "Cobalt Strike 4.5 (Dec 14, 2021)",
    0x619D3A40: "Cobalt Strike 4.5 (Dec 14, 2021)",
    0x6255EB4E: "Cobalt Strike 4.6 (Apr 12, 2022)",
    0x6255EB6E: "Cobalt Strike 4.6 (Apr 12, 2022)",
    0x6255EB91: "Cobalt Strike 4.6 (Apr 12, 2022)",
    0x62EBF2B8: "Cobalt Strike 4.7 (Aug 17, 2022)",
}
""" PE export timestamp to Cobalt Strike version mapping """


class BeaconVersion(str):
    """Helper class for dealing with Cobalt Strike version strings"""

    REGEX_VERSION = r"Cobalt Strike (?P<major>\d+)\.(?P<minor>\d+) \((?P<date>.*)\)"

    def __init__(self, version: str):
        self.version: str = version
        """full version string including date, e.g. ``"Cobalt Strike 4.5 (Dec 14, 2021)"``"""
        self.tuple: Optional[Tuple[int, int]] = None
        """the version as tuple of (major, minor), e.g. ``(4, 5)``. Otherwise, ``None``."""
        self.date: Optional[datetime.date] = None
        """date of version as :class:`datetime.date` object, e.g. ``datetime.date(2021, 12, 14)``.
        Otherwise, ``None``."""
        m = re.match(self.REGEX_VERSION, version)
        if m:
            self.date = datetime.datetime.strptime(m.group("date"), "%b %d, %Y").date()
            self.tuple = (int(m.group("major")), int(m.group("minor")))

    @classmethod
    def from_pe_export_stamp(cls, pe_export_stamp: int) -> "BeaconVersion":
        """Construct :class:`BeaconVersion` by looking up `pe_export_stamp` in
        the :attr:`PE_EXPORT_STAMP_TO_VERSION` map."""
        return BeaconVersion(PE_EXPORT_STAMP_TO_VERSION.get(pe_export_stamp, "Unknown"))

    @classmethod
    def from_max_setting_enum(cls, enum: int) -> "BeaconVersion":
        """Construct :class:`BeaconVersion` by looking up `enum` in the :attr:`MAX_ENUM_TO_VERSION` map."""
        return BeaconVersion(MAX_ENUM_TO_VERSION.get(enum, "Unknown"))

    @property
    def version_string(self) -> str:
        """The version string without the date. e.g. ``"Cobalt Strike 4.5"``"""
        return f"Cobalt Strike {self.version_only}"

    @property
    def version_only(self) -> str:
        """The version number only string. e.g. ``"4.5"``, or ``"Unknown"`` if version is unknown."""
        if not self.tuple:
            return "Unknown"
        return ".".join(map(str, self.tuple))

    def __str__(self):
        return self.version

    def __repr__(self):
        return f"<BeaconVersion {self.version!r}, tuple={self.tuple}, date={self.date}>"

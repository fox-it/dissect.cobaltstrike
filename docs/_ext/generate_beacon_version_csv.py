import csv
from datetime import datetime, timezone

from dissect.cobaltstrike.version import PE_EXPORT_STAMP_TO_VERSION


def setup(app):
    """Set up the extension"""
    app.connect("builder-inited", generate_csv)
    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }


def generate_csv(app):
    """Generate the CSV file"""
    with open("cobaltstrike-beacon-versions.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile, lineterminator="\n")
        writer.writerow(["Export Stamp", "Hex", "PE Export Date", "Cobalt Strike version"])
        for pe_export_stamp, version in sorted(PE_EXPORT_STAMP_TO_VERSION.items(), reverse=True):
            writer.writerow(
                [
                    pe_export_stamp,
                    f"0x{pe_export_stamp:08x}",
                    datetime.fromtimestamp(pe_export_stamp, timezone.utc).strftime("%a %b %d %H:%M:%S %Y"),
                    version,
                ]
            )

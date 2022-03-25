import sys

from dissect.cobaltstrike import utils


def find_xor_keys_artifact_kit(fh, start_offset: int = 0, maxrange: int = -1):
    fh.seek(start_offset)
    pos = fh.tell()
    while True:
        if maxrange > 0 and pos > maxrange:
            break
        fh.seek(pos)
        data = fh.read(4)
        if not data or len(data) != 4:
            break
        if pos + 16 == utils.u32(data):
            size = utils.u32(fh.read(4))
            xorkey = fh.read(4)
            hints = fh.read(8)
            data = fh.read(size)
            print(f"FOUND possible ArtifactKit offset: {pos}", file=sys.stderr)
            print(f"  - size: {size}", file=sys.stderr)
            print(f"  - 4-byte xorkey: {xorkey.hex()}", file=sys.stderr)
            print(f"  - hints: {hints}", file=sys.stderr)
            # Dump payload to stdout
            sys.stdout.buffer.write((utils.xor(data, xorkey)))
            return 1
        pos += 1
    return 0


with open(sys.argv[1], "rb") as f:
    if not find_xor_keys_artifact_kit(f):
        print("Not Artifact Kit", file=sys.stderr)

"""This module is responsible for debfuscating Cobalt Strike Beacon payloads that have been obfuscated using the
``stage.transform-obfuscate`` feature.

.. note::
    ``transform-obfuscate`` was introduced in Cobalt Strike 4.11:

    More information about ``transform-obfuscate`` can be found at:

    - https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping
    - https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/blog_cobalt-411-beacon_is_sleeping.htm
    - https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm
"""

import base64
import io
import logging
import sys
from typing import BinaryIO, Iterator, TypeAlias

from Crypto.Cipher import ARC4
from dissect.util.compression import lznt1

from dissect.cobaltstrike.c_obfuscate import c_obfuscate
from dissect.cobaltstrike.utils import xor

log = logging.getLogger(__name__)

ObfuscationType: TypeAlias = c_obfuscate.ObfuscationType
StageEvasionSettingsV1: TypeAlias = c_obfuscate.StageEvasionSettingsV1
StageEvasionSettingsV2: TypeAlias = c_obfuscate.StageEvasionSettingsV2
StageObfuscateSettings: TypeAlias = c_obfuscate.StageObfuscateSettings

StageEvasionSettings: TypeAlias = StageEvasionSettingsV1 | StageEvasionSettingsV2


def iter_find_evasion_settings(fh: BinaryIO) -> Iterator[tuple[StageEvasionSettings, int]]:
    """Iterate over possible StageEvasionSettings structures in file-like object `fh`.

    Arguments:
        fh: file-like object to search for StageEvasionSettings+StageObfuscateSettings structures

    Yields:
        Tuple of (StageEvasionSettings, ob_offset) where `ob_offset` is the offset to the StageObfuscateSettings struct
    """

    size = fh.seek(0, io.SEEK_END)
    for i in range(size):
        try:
            for ev_cls in (StageEvasionSettingsV1, StageEvasionSettingsV2):
                fh.seek(i)
                ev = ev_cls(fh)
                ob = StageObfuscateSettings(fh)
                ob_offset = fh.tell() - len(ob)
                if ObfuscatedBeacon._is_valid_obfuscated_stage(ev, ob):
                    log.debug("Found at offset 0x%x: %s", i, ev)
                    log.debug("Found at offset 0x%x: %s", ob_offset, ob)
                    log.debug("evasion max_size=%u, payload_size=%u", ev.max_size, ev.payload_size)
                    yield ev, ob_offset

        except EOFError:
            continue


class ObfuscatedBeacon(io.RawIOBase):
    """A file-like object representing an obfuscated Beacon payload.
    It deobfuscates the payload during initialization and exposes it for reading.

    Arguments:
        fh: file-like object containing the obfuscated Beacon payload
        evasion_offset: int: offset to the StageEvasionSettings structure
    """

    def __init__(self, fh: BinaryIO, offset: int) -> None:
        self.obfuscated_offset = offset
        """ Offset to the StageObfuscatedPayload structure """

        self.org_fh = fh
        fh.seek(self.obfuscated_offset)
        self.settings = StageObfuscateSettings(fh)
        self.key = fh.read(self.settings.key_size)
        obfuscated_payload = fh.read(self.settings.payload_size)
        self.leftover = fh.read()

        match self.settings.obfuscation_type:
            case ObfuscationType.OBFUSCATION_XOR:
                self.deobfuscated_payload = xor(obfuscated_payload, self.key)
            case ObfuscationType.OBFUSCATION_NONE:
                self.deobfuscated_payload = obfuscated_payload
            case ObfuscationType.OBFUSCATION_RC4:
                self.deobfuscated_payload = ARC4.new(self.key).decrypt(obfuscated_payload)
            case ObfuscationType.OBFUSCATION_BASE64:
                self.deobfuscated_payload = base64.b64decode(obfuscated_payload)
            case ObfuscationType.OBFUSCATION_LZNT1:
                self.deobfuscated_payload = lznt1.decompress(obfuscated_payload)
            case _:
                raise ValueError(f"Unknown obfuscation type: {self.settings.obfuscation_type}")

        self.fh = io.BytesIO(self.deobfuscated_payload)

    def __repr__(self) -> str:
        s = self.settings
        return (
            f"<ObfuscatedBeacon offset=0x{self.obfuscated_offset:x} "
            f"obfuscation={s.obfuscation_type} key_size={s.key_size} "
            f"original_size={s.original_size} payload_size={s.payload_size}>"
        )

    def get_name(self) -> str:
        return f"ObfuscatedBeacon({self.settings.obfuscation_type.name})"

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """Seek to a position in the deobfuscated payload."""
        return self.fh.seek(offset, whence)

    def read(self, size: int = -1) -> bytes:
        """Read and deobfuscate the Beacon payload."""
        return self.fh.read(size)

    @staticmethod
    def _is_valid_obfuscated_stage(ev: StageEvasionSettings, ob: StageObfuscateSettings) -> bool:
        """Validate evasion and obfuscation settings."""
        # Binary flags check
        if isinstance(ev, StageEvasionSettingsV1):
            binary_flags_valid = all(v in (0, 1) for v in (ev.copy_pe_header, ev.eaf_bypass, ev.rdll_use_syscalls))
        else:
            binary_flags_valid = all(
                v in (0, 1) for v in (ev.copy_pe_header, ev.eaf_bypass, ev.rdll_use_driploading, ev.rdll_use_syscalls)
            )

        # Obfuscation type check
        obfuscation_valid = ob.obfuscation_type in ObfuscationType

        # Key size check
        key_size_valid = (ob.key_size >= 8 and ob.key_size <= 2048) or ob.key_size == 0

        # Size/payload check
        size_valid = (
            ob.payload_size > 0
            and ob.original_size > 0
            and (ev.payload_size - 16 - ob.key_size) == ob.payload_size
            and ev.max_size >= max(ob.original_size, ob.payload_size)
        )
        return binary_flags_valid and obfuscation_valid and key_size_valid and size_valid


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Deobfuscate Cobalt Strike obfuscated Beacon stages.")
    parser.add_argument("input", help="Input file containing obfuscated Beacon stages")
    parser.add_argument(
        "--output", "-o", help="Output file for deobfuscated Beacon payload (default: stdout)", default=None
    )
    parser.add_argument(
        "--stage-offset",
        "-s",
        help="Offset to the StageObfuscateSettings structure (default: autodetect)",
        type=lambda x: int(x, 0),
        default=None,
    )
    parser.add_argument("--list-stages", "-l", help="List all obfuscated stages", action="store_true")
    parser.add_argument("--verbose", "-v", help="Enable verbose logging (incremental)", action="count", default=0)
    args = parser.parse_args()

    if args.verbose >= 2:
        log.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.WARNING)

    logging.basicConfig()

    with open(args.input, "rb") as fh:
        if args.stage_offset is not None:
            log.info("Processing evasion settings at offset 0x%x", args.stage_offset)
            obf = ObfuscatedBeacon(fh, args.stage_offset)
            if args.output:
                with open(args.output, "wb") as out_fh:
                    out_fh.write(obf.read())
            else:
                sys.stdout.buffer.write(obf.read())
            return

        stages: list[ObfuscatedBeacon] = []
        for ev, ob_offset in iter_find_evasion_settings(fh):
            log.info("Found evasion settings at offset 0x%x: %s", ob_offset, ev)
            obf = ObfuscatedBeacon(fh, offset=ob_offset)
            stages.append(obf)
            while obf.settings.obfuscation_type != ObfuscationType.OBFUSCATION_NONE:
                obf = ObfuscatedBeacon(obf, offset=0)
                stages.append(obf)
            break  # only process first found

        if args.list_stages:
            for stage, obf in enumerate(stages):
                s = obf.settings
                print(
                    f"Stage {stage}: {s.obfuscation_type}, key_size={s.key_size}, "
                    f"original_size={s.original_size}, payload_size={s.payload_size}, "
                    f"leftover={len(obf.leftover)}",
                    file=sys.stderr,
                )
            return

        if not stages:
            print("No payload stages found", file=sys.stderr)
        else:
            print("Dumping final deobfuscated payload to stdout:", file=sys.stderr)
            sys.stdout.buffer.write(stages[-1].read())


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import collections
import io
import logging
import sys
from typing import TYPE_CHECKING, BinaryIO, Protocol

from dissect.cobaltstrike.artifact import iter_artifactkit_payloads
from dissect.cobaltstrike.obfuscate import ObfuscatedBeacon, ObfuscationType, iter_find_evasion_settings
from dissect.cobaltstrike.pe import find_mz_offset
from dissect.cobaltstrike.utils import iter_find_needle, u32
from dissect.cobaltstrike.xordecode import XorEncodedFile, iter_nonce_offsets

if TYPE_CHECKING:
    from collections.abc import Iterator


logger = logging.getLogger(__name__)


class BeaconStage(Protocol):
    """Protocol for a Beacon stage, which can be a file-like object or an ObfuscatedBeacon."""

    def get_name(self) -> str:
        """Return the name of the Beacon stage."""
        ...


def is_pe(fh: BinaryIO) -> bool:
    """Check if the file-like object `fh` contains a PE header.

    Arguments:
        fh: file-like object to check for a PE header

    Returns:
        True if a valid PE header is found (in the first 1024 bytes), False otherwise.
    """
    return find_mz_offset(fh) is not None


def obfuscated_beacon_stages(fh: BinaryIO, require_pe: bool = False) -> list[ObfuscatedBeacon]:
    """Return a single chain of ObfuscatedBeacon stages found in `fh`.

    Arguments:
        fh: file-like object to search for ObfuscatedBeacon stages
        require_pe: if True, return the first chain whose final stage contains a PE header

    Returns:
        List of deobfuscated stages, or an empty list if no suitable stage is found.
    """
    MAX_STAGE_CHAIN_DEPTH = 32

    for ev, ob_offset in iter_find_evasion_settings(fh):
        logger.info("Found start of evasion settings at offset 0x%x: %s", ob_offset, ev)

        try:
            obf = ObfuscatedBeacon(fh, offset=ob_offset)
            stages = [obf]
            # Keep deobfuscating until we reach a non-obfuscated stage.
            while obf.settings.obfuscation_type != ObfuscationType.OBFUSCATION_NONE:
                if len(stages) >= MAX_STAGE_CHAIN_DEPTH:
                    logger.debug(
                        "Skipping candidate at offset 0x%x: exceeded max stage chain depth (%d)",
                        ob_offset,
                        MAX_STAGE_CHAIN_DEPTH,
                    )
                    break

                logger.debug(
                    "Deobfuscating stage (max_size: %d): %s",
                    max(obf.settings.original_size, obf.settings.payload_size),
                    obf,
                )
                obf = ObfuscatedBeacon(obf, offset=0)
                stages.append(obf)
            else:
                if not require_pe or is_pe(stages[-1]):
                    return stages
        except Exception as exc:
            logger.debug(
                "Skipping invalid obfuscated stage candidate at offset 0x%x: %s",
                ob_offset,
                exc,
            )

    return []


def xorencoded_beacon_candidates(fh: BinaryIO, maxrange: int = 1024) -> Iterator[XorEncodedFile]:
    EOF_SHELLCODE_MARKER = b"\xff\xff\xff"
    nonce_offsets = list(iter_nonce_offsets(fh, maxrange=maxrange))
    eof_shellcode_offsets = [
        offset + len(EOF_SHELLCODE_MARKER)
        for offset in iter_find_needle(fh, EOF_SHELLCODE_MARKER, start_offset=0, max_offset=maxrange)
    ]
    logger.debug(f"Found nonce offset candidates: {nonce_offsets}")
    logger.debug(f"Found eof_shellcode offset candidates: {eof_shellcode_offsets}")

    fh.seek(0, io.SEEK_END)
    file_size = fh.tell()

    # Try the most common eof_shellcode and nonce offset candidates first
    found_nonce_offset = None
    for offset, count in collections.Counter(eof_shellcode_offsets + nonce_offsets).most_common():
        logger.debug(f"Trying nonce offset: {offset} ({count})")
        found_nonce_offset = offset
        fh.seek(found_nonce_offset)
        nonce = fh.read(4)
        encoded_size = fh.read(4)
        real_size = u32(nonce) ^ u32(encoded_size)
        if real_size == file_size - (found_nonce_offset + 8):
            logger.info("Found valid nonce offset: %d", found_nonce_offset)
            yield XorEncodedFile.from_file(fh, nonce_offset=found_nonce_offset)
    return


def get_beacon_stages(fh: BinaryIO) -> list[BeaconStage]:
    stages: list[BinaryIO] = []

    # strategy 0: isPE -> ArtifactKit -> *
    if is_pe(fh):
        # Possible ArtifactKit payload, try to decode it.
        saw_artifact = False
        for artifact in iter_artifactkit_payloads(fh):
            saw_artifact = True
            logger.info("FOUND possible ArtifactKit offset: %s", artifact.offset)
            logger.info("  - size: %s", artifact.size)
            logger.info("  - 4-byte xorkey: %r", artifact.xorkey)
            logger.info("  - hints: %r", artifact.hints)
            logger.info("  - payload (preview): %r", artifact.payload[:20])
            if result := get_beacon_stages(artifact):
                return [artifact, *result]
        if saw_artifact:
            logger.info("ArtifactKit did not yield any beacon")

    # strategy 1: XorEncodedFile -> BeaconPE
    # strategy 2: XorEncodedFile -> ObfuscatedBeacon -> BeaconPE
    for xf in xorencoded_beacon_candidates(fh):
        if is_pe(xf):
            logger.info("PE FOUND")
            return [xf]

        if obf_stages := obfuscated_beacon_stages(xf, require_pe=True):
            return [xf, *obf_stages]

    # strategy 3: ObfuscatedBeacon -> BeaconPE
    if obf_stages := obfuscated_beacon_stages(fh, require_pe=True):
        return obf_stages

    return stages


if __name__ == "__main__":
    import logging
    import sys

    logging.basicConfig(level=logging.DEBUG)

    for name in sys.argv[1:]:
        logger.info(f"Processing {name}")
        with open(name, "rb") as f:
            stages = get_beacon_stages(f)
            stage_chain = " -> ".join(stage.get_name() for stage in stages)
            logger.info(f"Found {len(stages)} stage(s) in {name}:")
            logger.info("stages: %s", stage_chain)
            for stage in stages:
                logger.info(f"  - {stage}")

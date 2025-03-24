"""
This module is responsible for finding and recovering Beacon Guardrails configuration from Cobalt Strike payloads.
Guardrails is an additional layer of protection to the beacon config by using environmental keying (`T1480`_).

Beacon Guardrails was introduced in Cobalt Strike 4.8:

 - https://www.cobaltstrike.com/blog/cobalt-strike-4-8-system-call-me-maybe

Other research on Beacon Guardrails:

 - https://itea.org/journals/volume-45-3/cobalt-strike-cyber-assessment-challenge/

.. _T1480: https://attack.mitre.org/techniques/T1480/
"""

from __future__ import annotations

import collections
import functools
import io
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from dissect.cobaltstrike.utils import grouper, u32be, xor
from dissect.cstruct import cstruct

if TYPE_CHECKING:
    from collections.abc import Iterator

log = logging.getLogger(__name__)

C_GUARDRAILS_DEF = """
enum GuardOption: uint16 {
    GUARD_USER = 5,
    GUARD_COMPUTER = 6,
    GUARD_DOMAIN = 7,
    GUARD_LOCAL_IP = 8,
    GUARD_PAYLOAD_CHECKSUM = 9,
};

enum SettingsType: uint16 {
    TYPE_NONE = 0,
    TYPE_SHORT = 1,
    TYPE_INT = 2,
    TYPE_PTR = 3,
};

struct GuardrailSetting {
    GuardOption option;         // uint16
    SettingsType type;          // uint16
    uint16 length;              // uint16
    char value[length];
};
"""

BEACON_CONFIG_PATCH_SIZE = 6144
GUARD_PATCH_SIZE = 2048

GUARD_CONFIG_STARTS = [
    b"\x00\x05\x00\x01\x00\x02",  # GUARD_USER
    b"\x00\x06\x00\x01\x00\x02",  # GUARD_COMPUTER
    b"\x00\x07\x00\x01\x00\x02",  # GUARD_DOMAIN
    b"\x00\x08\x00\x02\x00\x04",  # GUARD_LOCAL_IP
]

c_guardrails = cstruct(endian=">").load(C_GUARDRAILS_DEF)
GuardrailSetting = c_guardrails.GuardrailSetting
GuardOption = c_guardrails.GuardOption


@dataclass
class GuardrailMetadata:
    """Class for holding Guardrail related data"""

    beacon_config_offset: int
    """ Offset of the beacon configuration in the payload """
    guard_config_offset: int
    """ Offset of the guardrail configuration in the payload """
    masked_beacon_config: bytes
    """ Masked raw beacon configuration """
    masked_guard_config: bytes
    """ Masked raw guardrail configuration """
    beacon_xor_key: bytes
    """ Single byte XOR key used to mask the beacon configuration. (0x2e by default unless modified beacon) """
    guardrail_xor_key: bytes
    """ Single byte XOR key used to unmask the guardrail configuration (0x8a by default unless modified beacon) """
    unmasked_guard_config: bytes
    """ Unmasked guardrail configuration """
    checksum: int
    """ Extracted payload checksum from guardrail configuration. This is used to validate the beacon configuration """
    payload_xor_key: bytes | None
    """ XOR key used to unmask the guarded beacon configuration. This is the environmental key """
    unmasked_beacon_config: bytes
    """ Unmasked beacon configuration """
    settings: list[GuardrailSetting]
    """ List of guardrail settings """


def iter_guardrail_configs(fh: BinaryIO, xorkey: bytes = b"\x8a") -> Iterator[GuardrailMetadata]:
    xorred_guardconfig_starts = [xor(x, xorkey) for x in GUARD_CONFIG_STARTS]
    size = len(xorred_guardconfig_starts[0])
    offset = 0
    while True:
        fh.seek(offset)
        block = fh.read(size * 2)
        if not block:
            break
        a, b = block[:size], block[size:]
        if xor(a[::-1], b) in xorred_guardconfig_starts:
            log.info("Found guardrail config at offset: %u in %r", offset, fh)
            guard_config_offset = offset + 6
            beacon_config_offset = guard_config_offset - BEACON_CONFIG_PATCH_SIZE
            fh.seek(beacon_config_offset)
            masked_beacon_config = fh.read(BEACON_CONFIG_PATCH_SIZE)
            masked_guard_config = fh.read(GUARD_PATCH_SIZE)
            unmasked_guard_config = xor(xor(masked_guard_config, masked_beacon_config[::-1]), xorkey)

            fh_guard = io.BufferedReader(io.BytesIO(unmasked_guard_config))
            checksum = 0
            settings: list[GuardrailSetting] = []
            while True:
                if fh_guard.peek(2)[:2] == b"\x00\x00":
                    break
                setting = GuardrailSetting(fh_guard)
                settings.append(setting)
                log.debug(setting)
                if setting.option == GuardOption.GUARD_PAYLOAD_CHECKSUM:
                    checksum = u32be(setting.value)
                    log.debug("%s = 0x%08x", setting.option.name, checksum)

            yield GuardrailMetadata(
                beacon_config_offset=beacon_config_offset,
                guard_config_offset=guard_config_offset,
                checksum=checksum,
                masked_guard_config=masked_guard_config,
                masked_beacon_config=masked_beacon_config,
                unmasked_guard_config=unmasked_guard_config,
                guardrail_xor_key=xorkey,
                beacon_xor_key=b"\x2e",  # we currently only support the XOR default key
                payload_xor_key=None,
                unmasked_beacon_config=None,
                settings=settings,
            )
        offset += 1


def find_xor_key_candidates(fh: BinaryIO) -> Iterator[bytes]:
    for keylen in range(2, 257):
        fh.seek(0)
        counter = collections.Counter()
        for chunk in iter(functools.partial(fh.read, io.DEFAULT_BUFFER_SIZE), b""):
            grams = grouper(chunk, n=keylen, fillvalue=0)
            counter.update(bytes(gram) for gram in grams)

        first_count = 0
        for key, count in counter.most_common(2):
            if count >= first_count:
                first_count = count
                yield key
            else:
                break


def payload_checksum(data: bytes) -> int:
    n = 0
    for i in range(len(data)):
        n = (n + (data[i] & 0xFF) * (i % 3 + 1)) % 99999999
    return n


def iter_guardrail_configs_with_beacon(fh: BinaryIO) -> Iterator[GuardrailMetadata]:
    for grconfig in iter_guardrail_configs(fh):

        # Unmask the beacon config, static single byte xor key should be 0x2E unless modified beacon
        # The beacon config is still masked with the environmental key
        grconfig.beacon_xor_key = b"\x2e"  # we currently only support the XOR default key
        guarded_config = xor(grconfig.masked_beacon_config, grconfig.beacon_xor_key)

        for xorkey in find_xor_key_candidates(io.BytesIO(guarded_config)):
            unguarded = xor(guarded_config, xorkey)

            checksum = payload_checksum(unguarded) + 1
            log.debug("payload checksum: 0x%08x for xorkey: %r", checksum, xorkey)

            if grconfig.checksum == checksum:
                log.info("Found guardrail payload xorkey: %r", xorkey)
                grconfig.payload_xor_key = xorkey
                grconfig.unmasked_beacon_config = unguarded
                yield grconfig
                break
        else:
            # No valid xor key found, so not able to unmask the beacon config
            # but we can still return the guardrail config
            yield grconfig

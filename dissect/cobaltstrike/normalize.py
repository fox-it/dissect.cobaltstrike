"""This module detects certain modifications in the beacon config and adapt it to the expected format for parsing.

Current seen and supported modifications:
    - Changes in the SettingsType enum values

"""

import io
import logging
import struct
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace

from dissect.cobaltstrike.beacon import (
    BeaconConfigBlock,
    BeaconModifications,
    BeaconSetting,
    Normalizer,
    SettingsType,
    iter_settings,
)

logger = logging.getLogger(__name__)


def settings_type_modifications(config_block: BeaconConfigBlock) -> dict[int, int]:
    """This function detects modifications to the SettingsType enum in the Beacon Configuration.

    It checks if any of the known settings have a different type than expected, indicating that the SettingsType enum
    has been modified.
    """

    # classify the settings by type and length, so we can detect if any of the known types have been modified.
    type_to_sizes = defaultdict(set[int])
    for setting in iter_settings(config_block.data):
        typ = int(setting.type)
        type_to_sizes[typ].add(int(setting.length))

    # Check if the known types have the expected sizes. If they do, we assume no modifications have been made.
    u32_sizes = type_to_sizes.get(int(SettingsType.TYPE_INT), {})
    u16_sizes = type_to_sizes.get(int(SettingsType.TYPE_SHORT), {})
    ptr_sizes = type_to_sizes.get(int(SettingsType.TYPE_PTR), {})
    if u32_sizes == {4} and u16_sizes == {2} and ptr_sizes:
        return {}

    u32_type = SettingsType.TYPE_INT
    u16_type = SettingsType.TYPE_SHORT
    ptr_type = SettingsType.TYPE_PTR

    for k, v in type_to_sizes.items():
        if v == {4}:
            u32_type = k
        elif v == {2}:
            u16_type = k
        elif v and any(size > 4 for size in v):
            ptr_type = k

    # Mapping of the type values found in the config block to the expected type values.
    return {
        int(u16_type): int(SettingsType.TYPE_SHORT),
        int(u32_type): int(SettingsType.TYPE_INT),
        int(ptr_type): int(SettingsType.TYPE_PTR),
    }


def _header(fh) -> tuple[int, int, int] | None:
    """Reads the next setting header from the file-like object and returns a tuple of (index, type, length)."""
    b = fh.read(6)
    if len(b) < 6:
        return None
    return struct.unpack(">HHH", b)  # index, type, length


def fix_settings_types(
    config_block: BeaconConfigBlock, mods: BeaconModifications
) -> tuple[BeaconConfigBlock, BeaconModifications]:
    """This function fixes any modified SettingsTypes in the ``BeaconConfigBlock``.

    Example hashes that have modified SettingsTypes:
        - a3a9d344b58d18a32780d8664bc0ba1018f0656e0d348e5d7d1c0166079bdab7
    """

    type_mapping = settings_type_modifications(config_block)
    if not type_mapping:
        return config_block, mods

    logger.debug("Detected remapped SettingsTypes: %s; normalizing", type_mapping)
    mods.tags.append("remapped_types")
    mods.remapped_types = type_mapping

    fh = io.BytesIO(config_block.data)
    while True:
        header = _header(fh)
        if header is None:
            break
        index, type_, length = header
        if correct_type := type_mapping.get(type_):
            logger.debug(
                "Fixing %s: SettingType(%s) -> %s",
                BeaconSetting(index).name,
                type_,
                SettingsType(correct_type).name,
            )
            fixed_header = struct.pack(">HHH", index, correct_type, length)
            fh.seek(-len(fixed_header), io.SEEK_CUR)  # Move back to the position of the type field
            fh.write(fixed_header)
        fh.seek(length, io.SEEK_CUR)  # Move to the next setting
        if index == 0:
            break

    fh.seek(0)
    block = replace(config_block, data=fh.getvalue())
    return block, mods


DEFAULT_NORMALIZERS: tuple[Normalizer, ...] = (fix_settings_types,)


def normalize_config_block(
    block: BeaconConfigBlock, *, normalizers: Sequence[Normalizer] | None = None
) -> tuple[BeaconConfigBlock, BeaconModifications]:
    """Run the normalizers against the ``config_block`` so it can normalize a modified beacon config.

    Args:
        block: The BeaconConfigBlock to normalize.
        normalizers: A sequence of normalizer functions to apply. If None, the default normalizers will be used.

    Returns:
        A tuple of the normalized BeaconConfigBlock and a BeaconModifications object describing the modifications made.
    """

    mods = BeaconModifications()
    for fn in DEFAULT_NORMALIZERS if normalizers is None else normalizers:
        block, mods = fn(block, mods)
    return block, mods

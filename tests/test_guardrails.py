import subprocess
import sys

import pytest

from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.guardrails import GUARD_CONFIG_STARTS, c_guardrails


def test_guard_config_start_size() -> None:
    """Test that all GUARD_CONFIG_STARTS have the same length."""
    sizes = map(len, GUARD_CONFIG_STARTS)
    assert len(set(sizes)) == 1


@pytest.mark.parametrize(
    "guard_option,settings_type,length",
    [
        (c_guardrails.GuardOption.GUARD_USER, c_guardrails.SettingsType.TYPE_SHORT, 2),
        (c_guardrails.GuardOption.GUARD_COMPUTER, c_guardrails.SettingsType.TYPE_SHORT, 2),
        (c_guardrails.GuardOption.GUARD_DOMAIN, c_guardrails.SettingsType.TYPE_SHORT, 2),
        (c_guardrails.GuardOption.GUARD_LOCAL_IP, c_guardrails.SettingsType.TYPE_INT, 4),
    ],
)
def test_guard_config_start_settings(guard_option, settings_type, length) -> None:
    """Test correctness of the known Guardrail start bytes by constructing the GuardrailSetting."""
    guard_option_user = c_guardrails.GuardrailSetting(
        option=guard_option,
        type=settings_type,
        length=length,
        value=b"",  # ignored
    ).dumps()
    assert guard_option_user in GUARD_CONFIG_STARTS


def test_beacon_dump_guardrails(guardrails_beacon_path):
    proc = subprocess.run(
        [sys.executable, "-m", "dissect.cobaltstrike.beacon", "-v", "-t", "normal", str(guardrails_beacon_path)],
        capture_output=True,
    )
    proc.check_returncode()
    stdout = proc.stdout
    stderr = proc.stderr

    assert b"Found guardrail payload xorkey: b'desktop-r4vgq8o'" in stderr
    assert b"guardrail payload xor key = b'desktop-r4vgq8o'" in stdout
    assert b"guardrail options = [<GuardOption.GUARD_COMPUTER: 6>, <GuardOption.GUARD_PAYLOAD_CHECKSUM: 9>]" in stdout


def test_beacon_guardrails_metadata(guardrails_beacon_file, beacon_x64_file):
    beacon = BeaconConfig.from_file(guardrails_beacon_file)
    assert beacon.guardrails is not None
    assert beacon.guardrails.payload_xor_key == b"desktop-r4vgq8o"
    assert beacon.guardrails.settings[0].option == c_guardrails.GuardOption.GUARD_COMPUTER
    assert beacon.guardrails.settings[1].option == c_guardrails.GuardOption.GUARD_PAYLOAD_CHECKSUM
    assert beacon.guardrails.checksum == 0xA5AD1
    assert beacon.guardrails.guardrail_xor_key == b"\x8a"

    beacon = BeaconConfig.from_file(beacon_x64_file)
    assert beacon.guardrails is None

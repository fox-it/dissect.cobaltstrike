"""
This module is responsible for extracting and parsing configuration from Cobalt Strike beacon payloads.
"""

from __future__ import annotations

import collections
import functools
import hashlib
import io
import ipaddress
import logging
import struct
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

from dissect import cstruct
from dissect.cobaltstrike import pe
from dissect.cobaltstrike.guardrails import GuardrailMetadata, iter_guardrail_configs_with_beacon
from dissect.cobaltstrike.obfuscate import ObfuscatedBeacon, StageObfuscateSettings
from dissect.cobaltstrike.stage import get_beacon_stages
from dissect.cobaltstrike.utils import (
    catch_sigpipe,
    grouper,
    iter_find_needle,
    iter_repeating_xor_key_candidates,
    p8,
    retain_file_offset,
    u16be,
    u32,
    u32be,
    xor,
)
from dissect.cobaltstrike.version import BeaconVersion
from dissect.cobaltstrike.xordecode import XorEncodedFile

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

CS_DEF = """
enum BeaconSetting: uint16 {
    SETTING_PROTOCOL = 1,
    SETTING_PORT = 2,
    SETTING_SLEEPTIME = 3,
    SETTING_MAXGET = 4,
    SETTING_JITTER = 5,
    SETTING_MAXDNS = 6,
    SETTING_PUBKEY = 7,
    SETTING_DOMAINS = 8,
    SETTING_USERAGENT = 9,
    SETTING_SUBMITURI = 10,
    SETTING_C2_RECOVER = 11,
    SETTING_C2_REQUEST = 12,
    SETTING_C2_POSTREQ = 13,
    SETTING_SPAWNTO = 14,       // releasenotes.txt

    // CobaltStrike version >= 3.4 (27 Jul, 2016)
    SETTING_PIPENAME = 15,

    SETTING_KILLDATE_YEAR = 16,         // Deprecated since Cobalt Strike 4.7
    SETTING_BOF_ALLOCATOR = 16,         // Introduced in Cobalt Strike 4.7

    SETTING_KILLDATE_MONTH = 17,        // Deprecated since Cobalt Strike 4.8
    SETTING_SYSCALL_METHOD = 17,        // Introduced in Cobalt Strike 4.8

    SETTING_KILLDATE_DAY = 18,
    SETTING_DNS_IDLE = 19,
    SETTING_DNS_SLEEP = 20,

    // CobaltStrike version >= 3.5 (22 Sept, 2016)
    SETTING_SSH_HOST = 21,
    SETTING_SSH_PORT = 22,
    SETTING_SSH_USERNAME = 23,
    SETTING_SSH_PASSWORD = 24,
    SETTING_SSH_KEY = 25,
    SETTING_C2_VERB_GET = 26,
    SETTING_C2_VERB_POST = 27,
    SETTING_C2_CHUNK_POST = 28,
    SETTING_SPAWNTO_X86 = 29,
    SETTING_SPAWNTO_X64 = 30,

    // CobaltStrike version >= 3.6 (8 Dec, 2016)
    SETTING_CRYPTO_SCHEME = 31,

    // CobaltStrike version >= 3.7 (15 Mar, 2016)
    SETTING_PROXY_CONFIG = 32,
    SETTING_PROXY_USER = 33,
    SETTING_PROXY_PASSWORD = 34,
    SETTING_PROXY_BEHAVIOR = 35,

    // CobaltStrike version >= 3.8 (23 May 2017)
    SETTING_INJECT_OPTIONS = 36,    // Deprecated in Cobalt Strike 4.5
    SETTING_WATERMARKHASH = 36,     // Introduced in Cobalt Strike 4.5

    // CobaltStrike version >= 3.9  (Sept 26, 2017)
    SETTING_WATERMARK = 37,

    // CobaltStrike version >= 3.11 (April 9, 2018)
    SETTING_CLEANUP = 38,

    // CobaltStrike version >= 3.11 (May 24, 2018)
    SETTING_CFG_CAUTION = 39,

    // CobaltStrike version >= 3.12 (Sept 6, 2018)
    SETTING_KILLDATE = 40,
    SETTING_GARGLE_NOOK = 41,       // https://www.youtube.com/watch?v=nLTgWdXrx3U
    SETTING_GARGLE_SECTIONS = 42,
    SETTING_PROCINJ_PERMS_I = 43,
    SETTING_PROCINJ_PERMS = 44,
    SETTING_PROCINJ_MINALLOC = 45,
    SETTING_PROCINJ_TRANSFORM_X86 = 46,
    SETTING_PROCINJ_TRANSFORM_X64 = 47,

    SETTING_PROCINJ_ALLOWED = 48,           // Deprecated since Cobalt Strike 4.7
    SETTING_PROCINJ_BOF_REUSE_MEM = 48,     // Introduced in Cobalt Strike 4.7

    // CobaltStrike version >= 3.13 (Jan 2, 2019)
    SETTING_BINDHOST = 49,

    // CobaltStrike version >= 3.14 (May 4, 2019)
    SETTING_HTTP_NO_COOKIES = 50,
    SETTING_PROCINJ_EXECUTE = 51,
    SETTING_PROCINJ_ALLOCATOR = 52,
    SETTING_PROCINJ_STUB = 53,      // .self = MD5(cobaltstrike.jar)

    // CobaltStrike version >= 4.0 (Dec 5, 2019)
    SETTING_HOST_HEADER = 54,
    SETTING_EXIT_FUNK = 55,

    // CobaltStrike version >= 4.1 (June 25, 2020)
    SETTING_SSH_BANNER = 56,
    SETTING_SMB_FRAME_HEADER = 57,
    SETTING_TCP_FRAME_HEADER = 58,

    // CobaltStrike version >= 4.2 (Nov 6, 2020)
    SETTING_HEADERS_REMOVE = 59,

    // CobaltStrike version >= 4.3 (Mar 3, 2021)
    SETTING_DNS_BEACON_BEACON = 60,
    SETTING_DNS_BEACON_GET_A = 61,
    SETTING_DNS_BEACON_GET_AAAA = 62,
    SETTING_DNS_BEACON_GET_TXT = 63,
    SETTING_DNS_BEACON_PUT_METADATA = 64,
    SETTING_DNS_BEACON_PUT_OUTPUT = 65,
    SETTING_DNSRESOLVER = 66,
    SETTING_DOMAIN_STRATEGY = 67,
    SETTING_DOMAIN_STRATEGY_SECONDS = 68,
    SETTING_DOMAIN_STRATEGY_FAIL_X = 69,
    SETTING_DOMAIN_STRATEGY_FAIL_SECONDS = 70,

    // CobaltStrike version >= 4.5 (Dec 14, 2021)
    SETTING_MAX_RETRY_STRATEGY_ATTEMPTS = 71,
    SETTING_MAX_RETRY_STRATEGY_INCREASE = 72,
    SETTING_MAX_RETRY_STRATEGY_DURATION = 73,

    // CobaltStrike version >= 4.7 (Aug 17, 2022)
    SETTING_MASKED_WATERMARK = 74,

    // CobaltStrike version >= 4.9 (Sep 19, 2023)
    SETTING_HOST_PROFILE = 75,
    SETTING_DATA_STORE_SIZE = 76,

    // CobaltStrike version >= 4.10 (Jul 16, 2024)
    SETTING_HTTP_DATA_REQUIRED = 77,
    SETTING_BEACON_GATE = 78,

    // Cobalt Strike >= 4.11 (Mar 17, 2025)
    SETTING_C2_CHUNK_POST_PACKET_SIZE = 79,
    SETTING_C2_CHUNK_POST_POST_SIZE = 80,

    SETTING_DNS_DOH_ENABLED = 81,
    SETTING_DNS_DOH_VERB = 82,
    SETTING_DNS_DOH_USERAGENT = 83,
    SETTING_DNS_DOH_PROXY_SERVER = 84,
    SETTING_DNS_DOH_SERVERS = 85,
    SETTING_DNS_DOH_ACCEPT = 86,
    SETTING_DNS_DOH_HEADERS = 87,

    // Cobalt Strike >= 4.12 (Nov 24, 2025)
    SETTING_PROCINJ_DRIP_LOAD = 88,
    SETTING_PROCINJ_DRIP_LOAD_DELAY = 89,

    // Cobalt Strike >= 4.13 (June 10, 2026)
    SETTING_CHECKIN_DELAY = 91,
};

enum DeprecatedBeaconSetting: uint16 {
    SETTING_KILLDATE_YEAR = 16,
    SETTING_KILLDATE_MONTH = 17,
    SETTING_INJECT_OPTIONS = 36,
    SETTING_PROCINJ_ALLOWED = 48,
};

enum TransformStep: uint32 {
    APPEND = 1,
    PREPEND = 2,
    BASE64 = 3,
    PRINT = 4,
    PARAMETER = 5,
    HEADER = 6,
    BUILD = 7,
    NETBIOS = 8,
    _PARAMETER = 9,
    _HEADER = 10,
    NETBIOSU = 11,
    URI_APPEND = 12,
    BASE64URL = 13,
    STRREP = 14,
    MASK = 15,
    // CobaltStrike version >= 4.0 (Dec 5, 2019)
    _HOSTHEADER = 16,
};

enum SettingsType: uint16 {
    TYPE_NONE = 0,
    TYPE_SHORT = 1,
    TYPE_INT = 2,
    TYPE_PTR = 3,
};

struct Setting {
    BeaconSetting index;    // uint16
    SettingsType type;      // uint16
    uint16 length;          // uint16
    char value[length];
};

flag BeaconProtocol {
    http = 0,
    dns = 1,
    smb = 2,
    tcp = 4,
    https = 8,
    bind = 16
};

flag ProxyServer {
    MANUAL = 0,
    DIRECT = 1,
    PRECONFIG = 2,
    MANUAL_CREDS = 4
};

enum CryptoScheme: uint16 {
    CRYPTO_LICENSED_PRODUCT = 0,
    CRYPTO_TRIAL_PRODUCT = 1
};

enum InjectAllocator: uint8 {
    VirtualAllocEx = 0,
    NtMapViewOfSection = 1,
};


// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_process-injection.htm
enum InjectExecutor: uint8 {
    CreateThread = 1,
    SetThreadContext = 2,
    CreateRemoteThread = 3,
    RtlCreateUserThread = 4,
    NtQueueApcThread = 5,
    CreateThread_ = 6,
    CreateRemoteThread_ = 7,
    NtQueueApcThread_s = 8,
    // Cobalt Strike >= 4.11 (May 12, 2025)
    // - https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping
    // - https://whiteknightlabs.com/2025/05/19/harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion-part-2/
    ObfSetThreadContext = 9,
    ObfSetThreadContext_ = 10,
};

enum BofAllocator: uint16 {
    VirtualAlloc = 0,
    MapViewOfFile = 1,
    HeapAlloc = 2,
};

// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-gate.htm
struct BeaconGateOptions {
    uint8 InternetOpenA;        // commms
    uint8 InternetConnectA;
    uint8 VirtualAlloc;         // core
    uint8 VirtualAllocEx;
    uint8 VirtualProtect;
    uint8 VirtualProtectEx;
    uint8 VirtualFree;
    uint8 GetThreadContext;
    uint8 SetThreadContext;
    uint8 ResumeThread;
    uint8 CreateThread;
    uint8 CreateRemoteThread;
    uint8 OpenProcess;
    uint8 OpenThread;
    uint8 CloseHandle;
    uint8 CreateFileMappingA;
    uint8 MapViewOfFile;
    uint8 UnmapViewOfFile;
    uint8 VirtualQuery;
    uint8 DuplicateHandle;
    uint8 ReadProcessMemory;
    uint8 WriteProcessMemory;
    uint8 ExitThread;           // cleanup
};
"""

cs_struct = cstruct.cstruct(endian=">")
cs_struct.load(CS_DEF)

TransformStep = cs_struct.TransformStep
BeaconSetting = cs_struct.BeaconSetting
DeprecatedBeaconSetting = cs_struct.DeprecatedBeaconSetting
SettingsType = cs_struct.SettingsType
Setting = cs_struct.Setting
BeaconProtocol = cs_struct.BeaconProtocol
CryptoScheme = cs_struct.CryptoScheme
ProxyServer = cs_struct.ProxyServer
InjectAllocator = cs_struct.InjectAllocator
InjectExecutor = cs_struct.InjectExecutor
BofAllocator = cs_struct.BofAllocator
BeaconGateOptions = cs_struct.BeaconGateOptions

TYPE_INT = SettingsType.TYPE_INT
TYPE_SHORT = SettingsType.TYPE_SHORT
TYPE_PTR = SettingsType.TYPE_PTR
# lookup: STOCK_TYPE[BeaconSetting(index)]  (reused names: A & B == index)

STOCK_TYPE = {
    BeaconSetting.SETTING_PROTOCOL: {TYPE_SHORT},  # idx=1 n=189687 TYPE_SHORT=189687
    BeaconSetting.SETTING_PORT: {TYPE_SHORT},  # idx=2 n=189692 TYPE_SHORT=189692
    BeaconSetting.SETTING_SLEEPTIME: {TYPE_INT},  # idx=3 n=189695 TYPE_INT=189695
    BeaconSetting.SETTING_MAXGET: {TYPE_INT},  # idx=4 n=189693 TYPE_INT=189693
    BeaconSetting.SETTING_JITTER: {TYPE_SHORT},  # idx=5 n=189694 TYPE_SHORT=189694
    BeaconSetting.SETTING_MAXDNS: {TYPE_SHORT},  # idx=6 n=103847 TYPE_SHORT=103847
    BeaconSetting.SETTING_PUBKEY: {TYPE_PTR},  # idx=7 n=189694 TYPE_PTR=189694
    BeaconSetting.SETTING_DOMAINS: {TYPE_PTR},  # idx=8 n=189694 TYPE_PTR=189694
    BeaconSetting.SETTING_USERAGENT: {TYPE_PTR},  # idx=9 n=177848 TYPE_PTR=177848
    BeaconSetting.SETTING_SUBMITURI: {TYPE_PTR},  # idx=10 n=177848 TYPE_PTR=177848
    BeaconSetting.SETTING_C2_RECOVER: {TYPE_PTR},  # idx=11 n=177848 TYPE_PTR=177848
    BeaconSetting.SETTING_C2_REQUEST: {TYPE_PTR},  # idx=12 n=177848 TYPE_PTR=177848
    BeaconSetting.SETTING_C2_POSTREQ: {TYPE_PTR},  # idx=13 n=177842 TYPE_PTR=177842
    BeaconSetting.SETTING_SPAWNTO: {TYPE_SHORT, TYPE_PTR},  # idx=14 n=167524 TYPE_SHORT=82, TYPE_PTR=167442
    BeaconSetting.SETTING_PIPENAME: {TYPE_PTR},  # idx=15 n=92003 TYPE_PTR=92003
    BeaconSetting.SETTING_BOF_ALLOCATOR & DeprecatedBeaconSetting.SETTING_KILLDATE_YEAR: {
        TYPE_SHORT
    },  # idx=16 n=39661 TYPE_SHORT=39661; also DeprecatedBeaconSetting.SETTING_KILLDATE_YEAR
    BeaconSetting.SETTING_SYSCALL_METHOD & DeprecatedBeaconSetting.SETTING_KILLDATE_MONTH: {
        TYPE_SHORT,
        TYPE_INT,
    },  # idx=17 n=29531 TYPE_SHORT=10107, TYPE_INT=19424; also DeprecatedBeaconSetting.SETTING_KILLDATE_MONTH
    BeaconSetting.SETTING_KILLDATE_DAY: {TYPE_SHORT},  # idx=18 n=10107 TYPE_SHORT=10107
    BeaconSetting.SETTING_DNS_IDLE: {TYPE_INT},  # idx=19 n=103844 TYPE_INT=103844
    BeaconSetting.SETTING_DNS_SLEEP: {TYPE_INT},  # idx=20 n=103844 TYPE_INT=103844
    BeaconSetting.SETTING_C2_VERB_GET: {TYPE_PTR},  # idx=26 n=189289 TYPE_PTR=189289
    BeaconSetting.SETTING_C2_VERB_POST: {TYPE_PTR},  # idx=27 n=189290 TYPE_PTR=189290
    BeaconSetting.SETTING_C2_CHUNK_POST: {TYPE_INT},  # idx=28 n=189288 TYPE_INT=189288
    BeaconSetting.SETTING_SPAWNTO_X86: {TYPE_PTR},  # idx=29 n=189289 TYPE_PTR=189289
    BeaconSetting.SETTING_SPAWNTO_X64: {TYPE_PTR},  # idx=30 n=189288 TYPE_PTR=189288
    BeaconSetting.SETTING_CRYPTO_SCHEME: {TYPE_SHORT},  # idx=31 n=189207 TYPE_SHORT=189207
    BeaconSetting.SETTING_PROXY_CONFIG: {TYPE_PTR},  # idx=32 n=589 TYPE_PTR=589
    BeaconSetting.SETTING_PROXY_USER: {TYPE_PTR},  # idx=33 n=136 TYPE_PTR=136
    BeaconSetting.SETTING_PROXY_PASSWORD: {TYPE_PTR},  # idx=34 n=136 TYPE_PTR=136
    BeaconSetting.SETTING_PROXY_BEHAVIOR: {TYPE_SHORT},  # idx=35 n=188454 TYPE_SHORT=188454
    BeaconSetting.SETTING_WATERMARKHASH & DeprecatedBeaconSetting.SETTING_INJECT_OPTIONS: {
        TYPE_SHORT,
        TYPE_PTR,
    },  # idx=36 n=48560 TYPE_SHORT=8623, TYPE_PTR=39937; also DeprecatedBeaconSetting.SETTING_INJECT_OPTIONS
    BeaconSetting.SETTING_WATERMARK: {TYPE_INT},  # idx=37 n=184359 TYPE_INT=184359
    BeaconSetting.SETTING_CLEANUP: {TYPE_SHORT},  # idx=38 n=183663 TYPE_SHORT=183663
    BeaconSetting.SETTING_CFG_CAUTION: {TYPE_SHORT},  # idx=39 n=182754 TYPE_SHORT=182754
    BeaconSetting.SETTING_KILLDATE: {TYPE_INT},  # idx=40 n=179566 TYPE_INT=179566
    BeaconSetting.SETTING_GARGLE_NOOK: {TYPE_INT},  # idx=41 n=179572 TYPE_INT=179572
    BeaconSetting.SETTING_GARGLE_SECTIONS: {TYPE_PTR},  # idx=42 n=63910 TYPE_PTR=63910
    BeaconSetting.SETTING_PROCINJ_PERMS_I: {TYPE_SHORT},  # idx=43 n=179573 TYPE_SHORT=179573
    BeaconSetting.SETTING_PROCINJ_PERMS: {TYPE_SHORT},  # idx=44 n=179574 TYPE_SHORT=179574
    BeaconSetting.SETTING_PROCINJ_MINALLOC: {TYPE_INT},  # idx=45 n=179573 TYPE_INT=179573
    BeaconSetting.SETTING_PROCINJ_TRANSFORM_X86: {TYPE_PTR},  # idx=46 n=179574 TYPE_PTR=179574
    BeaconSetting.SETTING_PROCINJ_TRANSFORM_X64: {TYPE_PTR},  # idx=47 n=179572 TYPE_PTR=179572
    BeaconSetting.SETTING_PROCINJ_BOF_REUSE_MEM & DeprecatedBeaconSetting.SETTING_PROCINJ_ALLOWED: {
        TYPE_SHORT
    },  # idx=48 n=42014 TYPE_SHORT=42014; also DeprecatedBeaconSetting.SETTING_PROCINJ_ALLOWED
    BeaconSetting.SETTING_HTTP_NO_COOKIES: {TYPE_SHORT},  # idx=50 n=167112 TYPE_SHORT=167112
    BeaconSetting.SETTING_PROCINJ_EXECUTE: {TYPE_PTR},  # idx=51 n=167111 TYPE_PTR=167111
    BeaconSetting.SETTING_PROCINJ_ALLOCATOR: {TYPE_SHORT},  # idx=52 n=167113 TYPE_SHORT=167113
    BeaconSetting.SETTING_PROCINJ_STUB: {TYPE_PTR},  # idx=53 n=166965 TYPE_PTR=166965
    BeaconSetting.SETTING_HOST_HEADER: {TYPE_PTR},  # idx=54 n=153069 TYPE_PTR=153069
    BeaconSetting.SETTING_EXIT_FUNK: {TYPE_SHORT},  # idx=55 n=153062 TYPE_SHORT=153062
    BeaconSetting.SETTING_SMB_FRAME_HEADER: {TYPE_PTR},  # idx=57 n=117702 TYPE_PTR=117702
    BeaconSetting.SETTING_TCP_FRAME_HEADER: {TYPE_PTR},  # idx=58 n=117701 TYPE_PTR=117701
    BeaconSetting.SETTING_HEADERS_REMOVE: {TYPE_PTR},  # idx=59 n=27 TYPE_PTR=27
    BeaconSetting.SETTING_DNS_BEACON_BEACON: {TYPE_PTR},  # idx=60 n=10839 TYPE_PTR=10839
    BeaconSetting.SETTING_DNS_BEACON_GET_A: {TYPE_PTR},  # idx=61 n=10838 TYPE_PTR=10838
    BeaconSetting.SETTING_DNS_BEACON_GET_AAAA: {TYPE_PTR},  # idx=62 n=10840 TYPE_PTR=10840
    BeaconSetting.SETTING_DNS_BEACON_GET_TXT: {TYPE_PTR},  # idx=63 n=10839 TYPE_PTR=10839
    BeaconSetting.SETTING_DNS_BEACON_PUT_METADATA: {TYPE_PTR},  # idx=64 n=10839 TYPE_PTR=10839
    BeaconSetting.SETTING_DNS_BEACON_PUT_OUTPUT: {TYPE_PTR},  # idx=65 n=10840 TYPE_PTR=10840
    BeaconSetting.SETTING_DNSRESOLVER: {TYPE_PTR},  # idx=66 n=10839 TYPE_PTR=10839
    BeaconSetting.SETTING_DOMAIN_STRATEGY: {TYPE_SHORT},  # idx=67 n=77599 TYPE_SHORT=77599
    BeaconSetting.SETTING_DOMAIN_STRATEGY_SECONDS: {TYPE_INT},  # idx=68 n=77597 TYPE_INT=77597
    BeaconSetting.SETTING_DOMAIN_STRATEGY_FAIL_X: {TYPE_INT},  # idx=69 n=77598 TYPE_INT=77598
    BeaconSetting.SETTING_DOMAIN_STRATEGY_FAIL_SECONDS: {TYPE_INT},  # idx=70 n=77599 TYPE_INT=77599
    BeaconSetting.SETTING_MAX_RETRY_STRATEGY_ATTEMPTS: {TYPE_INT},  # idx=71 n=40111 TYPE_INT=40111
    BeaconSetting.SETTING_MAX_RETRY_STRATEGY_INCREASE: {
        TYPE_SHORT,
        TYPE_INT,
    },  # idx=72 n=40113 TYPE_SHORT=1, TYPE_INT=40112
    BeaconSetting.SETTING_MAX_RETRY_STRATEGY_DURATION: {TYPE_INT},  # idx=73 n=40111 TYPE_INT=40111
    BeaconSetting.SETTING_MASKED_WATERMARK: {TYPE_PTR},  # idx=74 n=29554 TYPE_PTR=29554
    BeaconSetting.SETTING_HOST_PROFILE: {TYPE_PTR},  # idx=75 n=6 TYPE_PTR=6
    BeaconSetting.SETTING_DATA_STORE_SIZE: {TYPE_INT},  # idx=76 n=12046 TYPE_INT=12046
    BeaconSetting.SETTING_HTTP_DATA_REQUIRED: {TYPE_SHORT},  # idx=77 n=54 TYPE_SHORT=54
    BeaconSetting.SETTING_BEACON_GATE: {TYPE_PTR},  # idx=78 n=3085 TYPE_PTR=3085
    BeaconSetting.SETTING_C2_CHUNK_POST_PACKET_SIZE: {TYPE_INT},  # idx=79 n=2078 TYPE_INT=2078
    BeaconSetting.SETTING_C2_CHUNK_POST_POST_SIZE: {TYPE_INT},  # idx=80 n=2079 TYPE_INT=2079
    BeaconSetting.SETTING_DNS_DOH_ENABLED: {TYPE_SHORT},  # idx=81 n=135 TYPE_SHORT=135
    BeaconSetting.SETTING_DNS_DOH_VERB: {TYPE_SHORT},  # idx=82 n=96 TYPE_SHORT=96
    BeaconSetting.SETTING_DNS_DOH_USERAGENT: {TYPE_PTR},  # idx=83 n=135 TYPE_PTR=135
    BeaconSetting.SETTING_DNS_DOH_PROXY_SERVER: {TYPE_PTR},  # idx=84 n=3 TYPE_PTR=3
    BeaconSetting.SETTING_DNS_DOH_SERVERS: {TYPE_PTR},  # idx=85 n=135 TYPE_PTR=135
    BeaconSetting.SETTING_DNS_DOH_ACCEPT: {TYPE_PTR},  # idx=86 n=135 TYPE_PTR=135
    BeaconSetting.SETTING_DNS_DOH_HEADERS: {TYPE_PTR},  # idx=87 n=135 TYPE_PTR=135
    BeaconSetting.SETTING_PROCINJ_DRIP_LOAD: {TYPE_SHORT},  # idx=88 n=814 TYPE_SHORT=814
    BeaconSetting.SETTING_PROCINJ_DRIP_LOAD_DELAY: {TYPE_INT},  # idx=89 n=816 TYPE_INT=816
    BeaconSetting.SETTING_CHECKIN_DELAY: {TYPE_INT},  # idx=91 n=122 TYPE_INT=122
}
"""Mapping of stock beacon settings to their expected type. Can be used for validation."""

DEFAULT_XOR_KEYS: List[bytes] = [b"\x69", b"\x2e", b"\x00"]
""" Default XOR keys used by Cobalt Strike for obfuscating Beacon config bytes """

ASN1_RSA_ENCRYPTION = bytes.fromhex("06092A864886F70D010101")
""" rsaEncryption OID (1.2.840.113549.1.1.1) embedded in SETTING_PUBKEY """

_DER_SEQ_PREFIXES = (b"\x30\x81", b"\x30\x82")
""" DER SEQUENCE prefixes for SETTING_PUBKEY (SubjectPublicKeyInfo) """


@dataclass
class BeaconConfigBlock:
    """Class for holding Beacon configuration block data"""

    data: bytes
    """Raw (deobfuscated) bytes of the Beacon configuration block (PATCH_SIZE_V2 bytes)"""
    xorkey: bytes
    """XOR key used to deobfuscate the Beacon configuration block"""


@dataclass
class BeaconModifications:
    """Class for tracking modifications made to a Beacon configuration block"""

    tags: list[str] = field(default_factory=list)
    """List of tags associated with the Beacon config block (e.g., "remapped_types", "remapped_indexes")"""
    remapped_types: dict[int, int] = field(default_factory=dict)
    """Mapping of remapped setting types (type -> correct type) for the Beacon config block"""
    remapped_indexes: dict[int, int] = field(default_factory=dict)
    """Mapping of remapped setting indexes (index -> correct index) for the Beacon config block"""


Normalizer = Callable[
    [BeaconConfigBlock, BeaconModifications],
    tuple[BeaconConfigBlock, BeaconModifications],
]


def rotate_key(key: bytes, phase: int) -> bytes:
    n = len(key)
    phase %= n
    return key[phase:] + key[:phase]


class BeaconPatchSize(IntEnum):
    V1 = 0x1000  # Until Cobalt Strike 4.8, the beacon config was padded to 0x1000 bytes
    V2 = 0x1800  # Since Cobalt Strike 4.9, the beacon config is padded to 0x1800 bytes


PATCH_SIZE = max(BeaconPatchSize)

# Common SETTING lengths. Used only as a tie-breaker when ranking candidate configs. Not a strict validation.
_TYPICAL_SETTING_LENGTHS = frozenset({2, 4, 16, 32, 64, 128, 0x80, 0x100, 0x200, 0x400})


def _parse_setting_header(buf: bytes | memoryview, offset: int) -> Optional[Tuple[int, int, int]]:
    """Parse a big-endian ``(index, type, length)`` header at ``offset``, or ``None`` if truncated."""
    if offset + 6 > len(buf):
        return None
    return struct.unpack(">HHH", buf[offset : offset + 6])


def _looks_like_pubkey(body: bytes) -> bool:
    return body.startswith(_DER_SEQ_PREFIXES) or ASN1_RSA_ENCRYPTION in body


def _looks_like_domains(body: bytes) -> bool:
    host, sep, _rest = body.partition(b",")
    return bool(sep) and b"." in host


def walk_settings(
    buf: bytes | memoryview,
    max_length: int = 1024,
    packed: bool = True,
) -> list[int]:
    """Walk packed TLV settings in ``buf`` and return header offsets.

    Discovery treats a setting as an opaque ``uint16be index | type | length | value``.
    Index and type are **not** required to be stock ``BeaconSetting`` / ``SettingsType`` values.
    ``index == 0`` terminates the walk (end-of-config sentinel).
    """
    recs: list[int] = []
    i = 0
    n = len(buf)

    while i + 6 <= n:
        header = _parse_setting_header(buf, i)
        if header is None:
            break
        idx, _typ, ln = header
        if idx == 0:
            break
        if ln > max_length or i + 6 + ln > n:
            if packed:
                break
            i += 1
            continue
        recs.append(i)
        i += 6 + ln

    return recs


def setting_score(decoded: bytes | memoryview, recs: list[int]) -> tuple:
    """Rank a candidate config start using payload content, not enum values."""
    ids = []
    has_pubkey = has_domains = False
    typical = 0
    types = set()
    for off in recs:
        header = _parse_setting_header(decoded, off)
        if header is None:
            continue
        idx, _typ, ln = header
        types.add(_typ)
        ids.append(idx)
        body = decoded[off + 6 : off + 6 + min(ln, 256)]
        if isinstance(body, memoryview):
            body = body.tobytes()
        if _looks_like_pubkey(body):
            has_pubkey = True
        if _looks_like_domains(body):
            has_domains = True
        if ln in _TYPICAL_SETTING_LENGTHS:
            typical += 1

    unique = len(set(ids))
    known_indexes = sum(1 for idx in ids if idx in BeaconSetting)
    has_distinct_types = len(types) == 3
    return (
        int(has_pubkey) + int(has_domains) + int(has_distinct_types),
        known_indexes,
        unique,
        typical,
        len(recs),
    )


def find_beacon_config_bytes(fh: BinaryIO, xorkey: bytes) -> Iterator[BeaconConfigBlock]:
    r"""Find and yield (possible) Cobalt Strike configuration bytes from file `fh` using `xorkey` (eg: b"\x69").

    Discovery is payload-first: XOR-search for the RSA encryption OID embedded in
    ``SETTING_PUBKEY``, locate the covering TLV whose body contains that OID, then
    walk packed settings backward to recover the configuration start. Setting index
    and type values are treated as opaque; they are not required to match stock
    ``BeaconSetting`` / ``SettingsType`` enums.

    Args:
        fh: file object
        xorkey: XOR key (as bytes)

    Yields:
        Beacon configuration bytes (``PATCH_SIZE`` bytes), in deobfuscated (un-XOR'd) form.
    """
    klen = len(xorkey)
    if klen == 0:
        return

    for phase in range(klen):
        needle = xor(ASN1_RSA_ENCRYPTION, rotate_key(xorkey, phase))
        for pos in iter_find_needle(fh, needle, start_offset=0):
            logger.debug("ASN1_RSA_ENCRYPTION key=%r phase=%s @ 0x%x", xorkey, phase, pos)

            back_start = max(0, pos - PATCH_SIZE)
            fh.seek(back_start)
            back_data = fh.read(PATCH_SIZE * 3)
            phase_back = (phase + back_start - pos) % klen
            decoded_back = xor(back_data, rotate_key(xorkey, phase_back))
            decoded_view = memoryview(decoded_back)

            best = None
            for start in range(len(decoded_back)):
                recs = walk_settings(decoded_view[start:], packed=True)
                if len(recs) < 3:
                    continue
                score = setting_score(decoded_view[start:], recs)
                real_start = back_start + start
                if score[0] == 0:
                    continue

                logger.debug(
                    "config start 0x%x (relative: 0x%x) score=%r recs=%d",
                    real_start,
                    start,
                    score,
                    len(recs),
                )

                # Prefer payload evidence, then uniqueness; earlier start only as a tie-break.
                cand = (score, -real_start, decoded_view[start : start + PATCH_SIZE].tobytes())
                if best is None or cand > best:
                    best = cand

            if best is None:
                continue

            score, neg_real_start, decoded = best
            real_start = -neg_real_start
            phase_cfg = (phase + real_start - pos) % klen
            logger.debug("Found config start 0x%x score=%s", real_start, score)
            key = rotate_key(xorkey, phase_cfg)
            logger.debug("Found BeaconConfig using xorkey: %r (0x%x)", key, int.from_bytes(key, "big"))
            yield BeaconConfigBlock(data=decoded, xorkey=key)


def iter_beacon_config_blocks(fobj: BinaryIO, xor_keys=None, all_xor_keys=False) -> Iterator[BeaconConfigBlock]:
    """Yield found Beacon `config_block_bytes` from file `fobj` as `BeaconConfigBlock` instances.

    It always start seeking from the beginning of `fobj`. Side effects: file handle position due to seeking

    Args:
        xor_keys: list XOR keys (as bytes), defaults to: :attr:`DEFAULT_XOR_KEYS` if not specified.
        all_xor_keys: Try ALL single-byte XOR keys if no beacon config is found using the default keys.

    Yields:
        BeaconConfigBlock instances containing the found `config_block_bytes` and associated `xorkey`.
    """
    found = False
    xor_keys = xor_keys or DEFAULT_XOR_KEYS
    logger.debug(f"xor_keys: {xor_keys!r}")

    for xorkey in xor_keys:
        for config_block in find_beacon_config_bytes(fobj, xorkey):
            found = True
            yield config_block

    # Retry with left over xor keys if specified
    if not found and all_xor_keys:
        logger.debug("config_block not found, trying all xor keys...")
        # Determine left over xor keys
        left_xor_keys = make_byte_list(exclude=xor_keys)

        # Determine most common bytes in the (xordecoded) file
        bytes_counter = collections.Counter()
        for chunk in iter(functools.partial(fobj.read, io.DEFAULT_BUFFER_SIZE), b""):
            fourgrams = grouper(chunk, n=4, fillvalue=0)
            bytes_counter.update(gram[0] for gram in fourgrams if gram[0] == gram[1] == gram[2] == gram[3])
        most_common_bytes = [p8(x[0]) for x in bytes_counter.most_common()]

        # Sort left xor keys by most common bytes first
        left_xor_keys.sort(key=lambda x: most_common_bytes.index(x) if x in most_common_bytes else 256)

        logger.debug(f"left xor keys to try: {left_xor_keys}")
        yield from iter_beacon_config_blocks(fobj, left_xor_keys, all_xor_keys=False)


def make_byte_list(exclude: List[bytes] = None) -> List[bytes]:
    """Return all single-byte bytes as an ordered list, excluding `exclude` bytes."""
    return sorted({p8(x) for x in range(256)} - set(exclude or []))


def iter_settings(fobj: Union[bytes, BinaryIO], max_enum: int = 0) -> Iterator["Setting"]:
    """Returns an iterator yielding :class:`Setting` objects by reading data from `fobj`

    The file position will be at the end of the Beacon config after parsing is done.
    This can be used to determine the exact size of the Beacon configuration block.

    Some edge cases are also handled:

     - User-Agent string that exceeds the Setting length.
     - Deprecated setting SETTING_INJECT_OPTIONS

    Args:
        fobj: bytes or file-like object with Beacon configuration data
        max_enum: maximum BeaconSetting index seen so far, used to handle deprecated settings

    Yields:
        :class:`Setting` objects
    """
    if isinstance(fobj, bytes):
        fobj = io.BytesIO(fobj)

    while True:
        peek = fobj.read(2)[:2]
        if peek == b"\x00\x00":
            # end of beacon config
            break
        try:
            fobj.seek(-2, io.SEEK_CUR)
            setting = Setting(fobj)
        except EOFError:
            break
        max_enum = max(max_enum, setting.index)
        if setting.index == BeaconSetting.SETTING_USERAGENT:
            # Handle cases where User-Agent is too long in some configs, eg:
            # - fcece52fd030ca66043ae29af2116a79
            if setting.length == 0x80:
                if len(setting.value.rstrip(b"\x00")) >= 0x80:
                    while True:
                        x = fobj.read(1)
                        if x == b"\x00":
                            fobj.seek(-1, io.SEEK_CUR)
                            break
                        setting.value += x
        elif setting.index in (BeaconSetting.SETTING_C2_REQUEST, BeaconSetting.SETTING_C2_POSTREQ):
            # Handle cases the the C2_REQUEST or C2_POSTREQ setting is too long in some configs, eg:
            # - f2f0e82636dce9cc274fedc7a12a19dfcbada0861c6869507090913d7166ed23 (overflowed program)
            # - e6ce038b69e2e58b1e939f00c690c5fe8b834d4215687edc79d4c7f0b8989870 (overflowed program)
            # - 271baa4800a7d6d466a92fa77d3946f8e7376ac0116ecc72127953962662cb26 (truncated program)
            if setting.length == 0x100:
                # check if the length is respected and the program is truncated to the length
                with retain_file_offset(fobj):
                    recs = walk_settings(fobj.read(0x800))

                # otherwise the program is most likely longer than the length, so we need to read until the end
                # of the program
                if not recs:
                    real_size = setting.length
                    with retain_file_offset(fobj):
                        fobj.seek(-setting.length, io.SEEK_CUR)
                        transform_data = fobj.read(0x800)
                        ftransform = io.BytesIO(transform_data)
                        x = parse_transform_binary(ftransform)
                        real_size = ftransform.tell()
                        transform_data = transform_data[:real_size]

                    if real_size > setting.length:
                        logger.debug(f"Adjusting {setting.index} length from {setting.length} to {real_size}")
                        setting.value = transform_data
                        fobj.seek(-setting.length, io.SEEK_CUR)
                        fobj.seek(real_size, io.SEEK_CUR)
                        setting.length = real_size
        # Deprecated settings handling
        elif setting.index == BeaconSetting.SETTING_WATERMARKHASH and setting.type == SettingsType.TYPE_SHORT:
            # Handle deprecated setting INJECT_OPTIONS (SHORT) -> WATERMARKHASH (PTR)
            setting.index = BeaconSetting.SETTING_INJECT_OPTIONS
        elif setting.index == BeaconSetting.SETTING_SYSCALL_METHOD and setting.type == SettingsType.TYPE_SHORT:
            # Handle deprecated setting KILLDATE_MONTH (SHORT) -> SYSCALL_METHOD (INT)
            setting.index = BeaconSetting.SETTING_KILLDATE_MONTH
        elif setting.index == BeaconSetting.SETTING_BOF_ALLOCATOR and max_enum < 74:
            # Handle deprecated setting KILLDATE_YEAR (SHORT) -> BOF_ALLOCATOR (SHORT)
            # We can identify the difference using the max_enum value.
            setting.index = BeaconSetting.SETTING_KILLDATE_YEAR
        elif setting.index == BeaconSetting.SETTING_PROCINJ_BOF_REUSE_MEM and max_enum < 74:
            # Handle deprecated setting PROCINJ_ALLOWED (SHORT) -> PROCINJ_BOF_REUSE_MEM (SHORT)
            # We can identify the difference using the max_enum value.
            setting.index = BeaconSetting.SETTING_PROCINJ_ALLOWED

        yield setting


def parse_recover_binary(program: bytes) -> List[Tuple[str, Union[int, bool]]]:
    """Parse ``SETTING_C2_RECOVER`` (`.http-get.server.output`) data"""
    rsteps: List[Tuple[str, Union[int, bool]]] = []
    p = io.BytesIO(program)
    while True:
        d = p.read(4)
        if not d:
            break
        step = u32be(d)
        if step == TransformStep.APPEND:
            length = u32be(p.read(4))
            rsteps.append(("append", length))
        elif step == TransformStep.PREPEND:
            length = u32be(p.read(4))
            rsteps.append(("prepend", length))
        elif step == TransformStep.BASE64:
            rsteps.append(("base64", True))
        elif step == TransformStep.PRINT:
            rsteps.append(("print", True))
        elif step == TransformStep.NETBIOS:
            rsteps.append(("netbios", True))
        elif step == TransformStep.NETBIOSU:
            rsteps.append(("netbiosu", True))
        elif step == TransformStep.BASE64URL:
            rsteps.append(("base64url", True))
        elif step == TransformStep.MASK:
            rsteps.append(("mask", True))
        elif step == 0:
            break
        else:
            logger.error("Unknown recover step {}".format(step))
    return rsteps


def parse_transform_binary(
    program: bytes | io.BytesIO, build: str = "metadata"
) -> List[Tuple[str, Union[str, bytes, bool]]]:
    """Parse ``SETTING_C2_{REQUEST,POSTREQ}`` (`http-{get,post}.client`) data"""
    ENABLE_STEPS = [
        TransformStep.BASE64,
        TransformStep.BASE64URL,
        TransformStep.NETBIOS,
        TransformStep.NETBIOSU,
        TransformStep.URI_APPEND,
        TransformStep.PRINT,
        TransformStep.MASK,
    ]
    ARGUMENT_STEPS = [
        TransformStep._HEADER,
        TransformStep.HEADER,
        TransformStep.PARAMETER,
        TransformStep._PARAMETER,
        TransformStep._HOSTHEADER,
        TransformStep.APPEND,
        TransformStep.PREPEND,
    ]
    BUILD_MAP = {0: build, 1: "output"}

    tsteps: List[Tuple[str, Union[str, bytes, bool]]] = []
    if isinstance(program, bytes):
        p = io.BytesIO(program)
    else:
        p = program
    while True:
        d = p.read(4)
        value = u32be(d)
        if len(d) != 4 or value == 0:
            break
        step = TransformStep(value)
        name = step.name
        if step is None:
            raise IndexError("Unknown transform step for value: {}".format(value))
        elif step == TransformStep.BUILD:
            btype = u32be(p.read(4))
            bvalue = BUILD_MAP.get(btype, "UNKNOWN BUILD ARG")
            tsteps.append((name, bvalue))
        elif step in ENABLE_STEPS:
            tsteps.append((name, True))
        elif step in ARGUMENT_STEPS:
            length = u32be(p.read(4))
            arg = p.read(length)
            tsteps.append((name, arg))
        else:
            logger.error("Unknown transform step {}".format(step))
            p.seek(-4, io.SEEK_CUR)  # undo the read
            break
    return tsteps


def parse_execute_list(data: bytes) -> List[str]:
    """Parse ``SETTING_PROCINJ_EXECUTE`` (`.process-inject.execute`) data"""
    ret: List[str] = []
    p = io.BytesIO(data)
    while True:
        d = p.read(1)
        if not d or d == b"\x00":
            break
        inject = InjectExecutor(d)
        if inject in (
            InjectExecutor.CreateThread_,
            InjectExecutor.CreateRemoteThread_,
            InjectExecutor.ObfSetThreadContext_,
        ):
            s4 = u16be(p.read(2))
            length = u32be(p.read(4))
            s2 = p.read(length).rstrip(b"\x00")
            length = u32be(p.read(4))
            s3 = p.read(length).rstrip(b"\x00")
            s = "{}!{}".format(s2.decode(), s3.decode())
            if s4:
                s += "+0x{:x}".format(s4)
            ret.append('{} "{}"'.format(inject.name.rstrip("_"), s))
        else:
            ret.append(inject.name)
    return ret


def parse_process_injection_transform_steps(data: bytes) -> list:
    """Parse ``SETTING_PROCINJ_TRANSFORM_X{86,64}`` (`process-inject.transform-x{86,64}`) data"""
    steps = []
    p = io.BytesIO(data)
    d = p.read(4)
    if d:
        val = p.read(u32be(d))
        steps.append(("append", val))
    d = p.read(4)
    if d:
        val = p.read(u32be(d))
        steps.append(("prepend", val))
    return steps


def parse_gargle(data: bytes) -> list:
    """Parse ``SETTING_GARGLE_SECTIONS`` (`.stage.{sleep_mask,obfuscate,userwx}`) data"""
    addresses = []
    p = io.BytesIO(data)
    while True:
        d = p.read(4)
        if not d:
            break
        start = u32(d)
        end = u32(p.read(4))
        # addresses.append((x1, x2))
        # addresses.append((hex(x1), hex(x2)))
        # value = f"sectionAddress={x1:x}, sectionEnd={x2:x}"
        if (start, end) != (0, 0):
            value = f"0x{start:x}-0x{end:x}"
            addresses.append(value)
    return addresses


def parse_pivot_frame(data: bytes) -> bytes:
    """Parse ``SETTING_{TCP,SMB}_FRAME_HEADER`` (`.{tcp,smb}_frame_header`) data"""
    p = io.BytesIO(data)
    length = u16be(p.read(2))
    return p.read(length - 4)


def parse_beacon_gate(data: bytes) -> BeaconGateOptions:
    """Parse ``SETTING_BEACON_GATE`` (`.stage.beacon_gate`) data"""
    return BeaconGateOptions(data)


def beacon_gate_options_string(bgo: BeaconGateOptions) -> list[str]:
    """Return the enabled BeaconGate WinAPI's as a list of strings"""
    options = {k for k, v in bgo.__values__.items() if v}

    comms = {"InternetOpenA", "InternetConnectA"}
    core = {
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "VirtualFree",
        "GetThreadContext",
        "SetThreadContext",
        "ResumeThread",
        "CreateThread",
        "CreateRemoteThread",
        "OpenProcess",
        "OpenThread",
        "CloseHandle",
        "CreateFileMappingA",
        "MapViewOfFile",
        "UnmapViewOfFile",
        "VirtualQuery",
        "DuplicateHandle",
        "ReadProcessMemory",
        "WriteProcessMemory",
    }
    cleanup = {"ExitThread"}

    ret = []
    if options.issuperset(comms | core | cleanup):
        ret.append("All")
        options -= comms | core | cleanup

    if options.issuperset(comms):
        ret.append("Comms")
        options -= comms

    if options.issuperset(core):
        ret.append("Core")
        options -= core

    if options.issuperset(cleanup):
        ret.append("Cleanup")
        options -= cleanup

    ret.extend(options)
    return ret


def sha256sum_pubkey(der_data: bytes) -> str:
    """Return the SHA-256 digest of `der_data`"""
    return hashlib.sha256(der_data.rstrip(b"\x00")).hexdigest()


def null_terminated_bytes(data: bytes) -> bytes:
    r"""Return null terminated `data` as bytes.

    >>> null_terminated_bytes(b"Hello World\x00\x00Foobar\x00\x00")
    b'Hello World'
    >>> null_terminated_bytes(b"foo\xffbar\x00\x00\x00baz\x00")
    b'foo\xffbar'
    """
    a, _, _ = data.partition(b"\x00")
    return a


def null_terminated_str(data: bytes) -> str:
    r"""Return null terminated `data` as string. Non ascii characters are ignored.

    >>> null_terminated_str(b"Hello World\x00\x00foo bar\x00\x00")
    'Hello World'
    >>> null_terminated_str(b"Goodbye\xffPlanet\x00\x00")
    'GoodbyePlanet'
    """
    return null_terminated_bytes(data).decode("latin-1", "ignore")


def spawn_to_hex(data: bytes | int) -> str:
    """Return `data` as hex string. If `data` is an integer, it is converted to hex string with 0x prefix.

    The data should be bytes, but in some modified beacons it can be an integer instead. It handles both cases.
    """
    if isinstance(data, int):
        return f"0x{data:x}"
    return data.hex()


SETTING_TO_PRETTYFUNC: Dict[BeaconSetting, Callable] = {
    BeaconSetting.SETTING_PROCINJ_STUB: lambda x: x.hex(),
    BeaconSetting.SETTING_SPAWNTO: spawn_to_hex,
    BeaconSetting.SETTING_C2_RECOVER: parse_recover_binary,
    BeaconSetting.SETTING_C2_REQUEST: parse_transform_binary,
    BeaconSetting.SETTING_C2_POSTREQ: functools.partial(parse_transform_binary, build="id"),
    BeaconSetting.SETTING_PROCINJ_EXECUTE: parse_execute_list,
    BeaconSetting.SETTING_PROCINJ_TRANSFORM_X86: parse_process_injection_transform_steps,
    BeaconSetting.SETTING_PROCINJ_TRANSFORM_X64: parse_process_injection_transform_steps,
    BeaconSetting.SETTING_GARGLE_SECTIONS: parse_gargle,
    BeaconSetting.SETTING_TCP_FRAME_HEADER: parse_pivot_frame,
    BeaconSetting.SETTING_SMB_FRAME_HEADER: parse_pivot_frame,
    BeaconSetting.SETTING_DOMAINS: null_terminated_str,
    BeaconSetting.SETTING_HOST_HEADER: null_terminated_str,
    BeaconSetting.SETTING_C2_VERB_GET: null_terminated_str,
    BeaconSetting.SETTING_C2_VERB_POST: null_terminated_str,
    BeaconSetting.SETTING_PIPENAME: null_terminated_str,
    BeaconSetting.SETTING_SPAWNTO_X86: null_terminated_str,
    BeaconSetting.SETTING_SPAWNTO_X64: null_terminated_str,
    BeaconSetting.SETTING_USERAGENT: null_terminated_str,
    BeaconSetting.SETTING_SUBMITURI: null_terminated_str,
    # BeaconSetting.SETTING_PUBKEY: lambda x: x.rstrip(b"\x00"),
    BeaconSetting.SETTING_PUBKEY: sha256sum_pubkey,
    BeaconSetting.SETTING_DNS_BEACON_BEACON: null_terminated_str,
    BeaconSetting.SETTING_DNS_BEACON_GET_A: null_terminated_str,
    BeaconSetting.SETTING_DNS_BEACON_GET_AAAA: null_terminated_str,
    BeaconSetting.SETTING_DNS_BEACON_GET_TXT: null_terminated_str,
    BeaconSetting.SETTING_DNS_BEACON_PUT_METADATA: null_terminated_str,
    BeaconSetting.SETTING_DNS_BEACON_PUT_OUTPUT: null_terminated_str,
    BeaconSetting.SETTING_DNSRESOLVER: null_terminated_str,
    BeaconSetting.SETTING_DNS_IDLE: lambda x: str(ipaddress.IPv4Address(x)),
    BeaconSetting.SETTING_WATERMARKHASH: lambda x: null_terminated_bytes(x) if isinstance(x, bytes) else x,
    BeaconSetting.SETTING_MASKED_WATERMARK: lambda x: x.hex(),
    BeaconSetting.SETTING_BOF_ALLOCATOR: lambda x: BofAllocator(x).name,
    BeaconSetting.SETTING_BEACON_GATE: lambda x: beacon_gate_options_string(parse_beacon_gate(x)),
    BeaconSetting.SETTING_DNS_DOH_USERAGENT: null_terminated_str,
    BeaconSetting.SETTING_DNS_DOH_PROXY_SERVER: null_terminated_str,
    BeaconSetting.SETTING_DNS_DOH_SERVERS: null_terminated_str,
    BeaconSetting.SETTING_DNS_DOH_ACCEPT: null_terminated_str,
    BeaconSetting.SETTING_DNS_DOH_HEADERS: null_terminated_str,
    # BeaconSetting.SETTING_PROTOCOL: lambda x: BeaconProtocol(x).name,
    # BeaconSetting.SETTING_CRYPTO_SCHEME: lambda x: CryptoScheme(x).name,
    # BeaconSetting.SETTING_PROXY_BEHAVIOR: lambda x: ProxyServer(x).name,
}
"""BeaconSetting enum to pretty function mapping"""


class BeaconConfig:
    """A :class:`BeaconConfig` object represents a single Beacon configuration

    It holds configuration data, parsed settings and other metadata of a Cobalt Strike Beacon and provides useful
    methods and properties for accessing the Beacon settings. It does *not* contain the Beacon payload data itself.

    It can be directly instantiated using configuration data. Otherwise, use the following constructors:

     - :meth:`BeaconConfig.from_file`
     - :meth:`BeaconConfig.from_path`
     - :meth:`BeaconConfig.from_bytes`

     The **from_** constructors automatically tries to extract the configuration data (first candidate only) and also
     handles `xorencoded` payloads and `XOR` decoding of obfuscated configuration blocks that is common
     with Cobalt Strike.
    """

    def __init__(self, config_block: bytes) -> None:
        self.config_block: bytes = config_block
        """ Raw beacon configuration block bytes """
        self.settings_tuple: tuple[Setting, ...] = tuple(iter_settings(config_block))
        """ Tuple containing the `Setting` objects parsed from `config_block` """
        self.xorkey: Optional[bytes] = None
        """ XOR key that was used to obfuscate the configuration block, ``None`` if unknown. """
        self.xorencoded: bool = False
        """ ``True`` if the beacon was xorencoded, otherwise ``False`` """
        self.pe_export_stamp: Optional[int] = None
        """ PE export timestamp, ``None`` if unknown. """
        self.pe_compile_stamp: Optional[int] = None
        """ PE compile timestamp, ``None`` if unknown. """
        self.architecture: Optional[str] = None
        """ PE architecture, ``"x86"`` or ``"x64"`` and  ``None`` if unknown. """
        self.guardrails: Optional[GuardrailMetadata] = None
        """ Guardrails metadata, ``None`` if not available. """
        self.obfuscate_settings: List[StageObfuscateSettings] = []
        """ List of transform-obfuscate settings from the stages, empty list if not available. """
        self.stages: List[str] = []
        """ List of all obfuscation stages as names, empty list if not available. """
        self.modifications: Optional[BeaconModifications] = None
        """ Modifications applied to the beacon config. ``None`` if no modifications were applied. """

        # Used for caching
        self._settings: Optional[Mapping[str, Any]] = None
        self._settings_by_index: Optional[Mapping[int, Any]] = None
        self._raw_settings: Optional[Mapping[str, Any]] = None
        self._raw_settings_by_index: Optional[Mapping[int, Any]] = None

    @classmethod
    def _from_block(
        cls,
        config_block: BeaconConfigBlock,
        *,
        fh,
        xorencoded: bool,
        obfuscate_settings: list,
        stages: list[str],
        guardrails: GuardrailMetadata | None = None,
        normalizers: Sequence[Normalizer] | None = None,
    ) -> BeaconConfig:
        modifications = None

        if normalizers is None:
            from dissect.cobaltstrike.normalize import DEFAULT_NORMALIZERS

            normalizers = DEFAULT_NORMALIZERS

        if normalizers:
            from dissect.cobaltstrike.normalize import normalize_config_block

            config_block, modifications = normalize_config_block(config_block, normalizers=normalizers)

        bconfig = cls(config_block.data)
        bconfig.xorkey = guardrails.beacon_xor_key if guardrails is not None else config_block.xorkey
        bconfig.xorencoded = xorencoded
        bconfig.pe_compile_stamp, bconfig.pe_export_stamp = pe.find_compile_stamps(fh)
        bconfig.architecture = pe.find_architecture(fh)
        bconfig.obfuscate_settings = obfuscate_settings
        bconfig.stages = stages
        if modifications:
            bconfig.modifications = modifications
        bconfig.guardrails = guardrails
        return bconfig

    @classmethod
    def from_file(
        cls,
        fobj: BinaryIO,
        *,
        xor_keys: List[bytes] | None = None,
        all_xor_keys: bool = True,
        normalizers: Sequence[Normalizer] | None = None,
    ) -> "BeaconConfig":
        """Create a :class:`BeaconConfig` from file object, or raises ValueError if no beacon config is found.

        Args:
            fobj: file-like object
            xor_keys: override the default `XOR` keys (as bytes) when specified. Default ``None``.
            all_xor_keys: if ``True``, it will try ALL single-byte `XOR` keys if the defaults don't work
            normalizers: Normalize pipeline. ``None`` uses :data:`DEFAULT_NORMALIZERS`,
                        ``()`` skips normalization, a sequence replaces the pipeline.

        Returns:
            :class:`BeaconConfig`

        Raises:
            ValueError: If no valid beacon configuration was found
        """

        stages = get_beacon_stages(fobj)
        fh = fobj if not stages else stages[-1]

        is_xorencoded = any(isinstance(stage, XorEncodedFile) for stage in stages)
        obfuscate_settings = [stage.settings for stage in stages if isinstance(stage, ObfuscatedBeacon)]
        stage_names = [stage.get_name() for stage in stages]

        for config_block in iter_beacon_config_blocks(fh, xor_keys=xor_keys, all_xor_keys=all_xor_keys):
            return cls._from_block(
                config_block,
                fh=fh,
                xorencoded=is_xorencoded,
                obfuscate_settings=obfuscate_settings,
                stages=stage_names,
                normalizers=normalizers,
            )

        logger.debug("Checking for Guardrails protected Beacon config...")
        for grconfig in iter_guardrail_configs_with_beacon(fh):
            if not grconfig.unmasked_beacon_config:
                continue
            block = BeaconConfigBlock(
                data=grconfig.unmasked_beacon_config,
                xorkey=grconfig.beacon_xor_key,
            )
            return cls._from_block(
                block,
                fh=fh,
                xorencoded=is_xorencoded,
                obfuscate_settings=obfuscate_settings,
                stages=stage_names,
                guardrails=grconfig,
                normalizers=normalizers,
            )

        candidates = list(iter_repeating_xor_key_candidates(fh))
        logger.debug(f"multi-byte xor key candidates: {candidates}")
        for config_block in iter_beacon_config_blocks(fh, xor_keys=candidates, all_xor_keys=False):
            return cls._from_block(
                config_block,
                fh=fh,
                xorencoded=is_xorencoded,
                obfuscate_settings=obfuscate_settings,
                stages=stage_names,
                normalizers=normalizers,
            )

        raise ValueError("No valid Beacon configuration found")

    @classmethod
    def from_path(
        cls,
        path: Union[str, Path],
        *,
        xor_keys: List[bytes] | None = None,
        all_xor_keys: bool = True,
        normalizers: Sequence[Normalizer] | None = None,
    ) -> "BeaconConfig":
        """Create a :class:`BeaconConfig` from path, or raises ValueError if no beacon config is found.

        Args:
            path: path to file on disk
            xor_keys: override the default `XOR` keys (as bytes) when specified. Default ``None``.
            all_xor_keys: if ``True`` it will try ALL single-byte `XOR` keys if the defaults don't work
            normalizers: Normalize pipeline. ``None`` uses :data:`DEFAULT_NORMALIZERS`,
                        ``()`` skips normalization, a sequence replaces the pipeline.

        Returns:
            :class:`BeaconConfig`

        Raises:
            ValueError: If no valid beacon configuration was found
        """
        with open(path, "rb") as fobj:
            return cls.from_file(fobj, xor_keys=xor_keys, all_xor_keys=all_xor_keys, normalizers=normalizers)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        xor_keys: List[bytes] | None = None,
        all_xor_keys: bool = False,
        normalizers: Sequence[Normalizer] | None = None,
    ) -> "BeaconConfig":
        """Create a :class:`BeaconConfig` from bytes, or raises ValueError if no beacon config is found.

        Args:
            data: configuration bytes
            xor_keys: override the default `XOR` keys when specified. Default ``None``.
            all_xor_keys: if ``True`` it will try ALL single-byte `XOR` keys if the defaults don't work
            normalizers: Normalize pipeline. ``None`` uses :data:`DEFAULT_NORMALIZERS`,
                        ``()`` skips normalization, a sequence replaces the pipeline.

        Returns:
            :class:`BeaconConfig`

        Raises:
            ValueError: If no valid beacon configuration was found
        """
        return cls.from_file(io.BytesIO(data), xor_keys=xor_keys, all_xor_keys=all_xor_keys, normalizers=normalizers)

    def __repr__(self) -> str:
        return f"<BeaconConfig {self.domains}>"

    @property
    def setting_enums(self) -> list:
        """List of BeaconSetting `enum` values in the order of appearance within the Beacon configuration.
        Example value::

            [1, 2, 3, 4, 5, 7, ..., 45, 46, 47, 53, 51, 52]
        """
        return [s.index.value for s in self.settings_tuple]

    @property
    def max_setting_enum(self) -> int:
        """The maximum BeaconSetting `enum` value present in the Beacon configuration."""
        return max(self.setting_enums, default=0)

    def settings_map(self, index_type="enum", pretty=False, parse=True) -> MappingProxyType:
        """Return a read-only settings mapping indexed by given `index_type`.

        Args:
            index_type: index type of the dictionary, can be one of:

               - ``name``: indexed by `BeaconSetting` name (str)
               - ``const``: indexed by `BeaconSetting` constant (int)
               - ``enum``: indexed by `BeaconSetting` enum (enum object).

            pretty: if `True`, apply pretty functions on the values.
            parse: if `True`, the raw bytes of `TYPE_SHORT` and `TYPE_INT` values are converted to int.

        Returns:
            OrderedDict
        """
        settings = OrderedDict()
        for setting in self.settings_tuple:
            val = setting.value
            if index_type == "name":
                key = setting.index.name or str(setting.index).replace(".", "_")
            elif index_type == "const":
                key = setting.index.value
            else:
                key = setting.index
            if parse or pretty:
                if setting.type == SettingsType.TYPE_SHORT:
                    val = u16be(val)
                elif setting.type == SettingsType.TYPE_INT:
                    val = u32be(val)
            if pretty:
                pretty_func = SETTING_TO_PRETTYFUNC.get(setting.index)
                if pretty_func:
                    val = pretty_func(val)
            settings[key] = val
        return MappingProxyType(settings)

    @property
    def raw_settings(self) -> Mapping[str, Any]:
        r"""Read-only Beacon settings mapping with raw values, indexed by `BeaconSetting` name.

        The raw bytes of `TYPE_SHORT` and `TYPE_INT` values are converted to int.
        Example value::

            mappingproxy({
                'SETTING_PROTOCOL': 8,
                'SETTING_PORT': 443,
                'SETTING_SLEEPTIME': 60000,
                ...
                'SETTING_C2_VERB_POST': b'POST\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                'SETTING_PROCINJ_STUB': b'\x0c\xe2\xf5TD\xe4y5\x16\xb5\xaf\xe9g\xbe\x92U',
            })
        """
        if self._raw_settings is None:
            self._raw_settings = self.settings_map(index_type="name")
        return self._raw_settings

    @property
    def raw_settings_by_index(self) -> Mapping[int, Any]:
        r"""Read-only Beacon settings mapping with raw values, indexed by `BeaconSetting` constant.

        The raw bytes of `TYPE_SHORT` and `TYPE_INT` values are converted to int.
        Example value::

            mappingproxy({
                1: 8,
                2: 443,
                3: 60000,
                ...
                27: b'POST\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                53: b'\x0c\xe2\xf5TD\xe4y5\x16\xb5\xaf\xe9g\xbe\x92U',
            })
        """

        if self._raw_settings_by_index is None:
            self._raw_settings_by_index = self.settings_map(index_type="const")
        return self._raw_settings_by_index

    @property
    def settings(self) -> Mapping[str, Any]:
        r"""Read-only Beacon settings mapping with human readable values, indexed by `BeaconSetting` name.
        Example value::

            mappingproxy({
                'SETTING_PROTOCOL': 8,
                'SETTING_PORT': 443,
                'SETTING_SLEEPTIME': 60000,
                ...
                'SETTING_C2_VERB_POST': 'POST',
                'SETTING_PROCINJ_STUB': '0ce2f55444e4793516b5afe967be9255',
            })
        """
        if self._settings is None:
            self._settings = self.settings_map(index_type="name", pretty=True)
        return self._settings

    @property
    def settings_by_index(self) -> Mapping[int, Any]:
        r"""Read-only Beacon settings mapping with human readable values, indexed by `BeaconSetting` constant.
        Example value::

            mappingproxy({
                1: 8,
                2: 443,
                3: 60000,
                ...
                27: 'POST',
                53: '0ce2f55444e4793516b5afe967be9255',
            })
        """
        if self._settings_by_index is None:
            self._settings_by_index = self.settings_map(index_type="const", pretty=True)
        return self._settings_by_index

    @property
    def domain_uri_pairs(self) -> List[Tuple[str, str]]:
        """List of configured `(domain, uri)` pairs in the Beacon.
        Example value::

            [
                ('c1.example.com', '/__utm.gif'),
                ('c2.example.com', '/en_US/all.js'),
            ]
        """
        domains = self.raw_settings.get("SETTING_DOMAINS")
        if not isinstance(domains, bytes):
            return []
        return list(grouper(null_terminated_str(domains).split(","), 2))

    @property
    def uris(self) -> List[str]:
        """List of configured Beacon URIs.
        Example value::

            ['/__utm.gif', '/en_US/all.js']
        """
        return list(dict.fromkeys(uri for (_domain, uri) in self.domain_uri_pairs))

    @property
    def domains(self) -> List[str]:
        """List of configured Beacon domains.
        Example value::

            ['c1.example.com', 'c2.example.com']
        """
        return list(dict.fromkeys(domain for (domain, _uri) in self.domain_uri_pairs))

    @property
    def submit_uri(self) -> Optional[str]:
        """The submit URI that the beacon uses for sending callback data.
        Example value::

            '/submit.php'
        """
        return self.settings.get("SETTING_SUBMITURI", None)

    @property
    def killdate(self) -> Optional[str]:
        """Normalized kill date as YYYY-mm-dd string or ``None`` if not defined in Beacon.

        .. note::
            The reason why the return type is a :class:`str` instead of a :class:`datetime.date` object is that
            the configured `killdate` in the Beacon can be arbitrary. e.g. 9999-99-99
        """
        s = self.settings
        killdate = s.get("SETTING_KILLDATE", 0)
        if killdate:
            date_str = str(killdate)
            year = int(date_str[:4])
            month = int(date_str[4:6])
            day = int(date_str[6:8])
            killdate = f"{year:02d}-{month:02d}-{day:02d}"
        else:
            killdate = None
            year = s.get("SETTING_KILLDATE_YEAR", 0)
            month = s.get("SETTING_KILLDATE_MONTH", 0)
            day = s.get("SETTING_KILLDATE_DAY", 0)
            if year and month and day:
                killdate = f"{year:02d}-{month:02d}-{day:02d}"
        return killdate

    @property
    def protocol(self) -> Optional[str]:
        """The protocol the Beacon uses for communication, e.g. ``"http"``, ``"dns"``. ``None`` if unknown."""
        protocol = self.raw_settings.get("SETTING_PROTOCOL", None)
        if protocol is None:
            return None
        return BeaconProtocol(protocol).name

    @property
    def port(self) -> Optional[int]:
        """The port the Beacon uses for communication, e.g. ``80``, ``443``. ``None`` if not defined in config."""
        return self.raw_settings.get("SETTING_PORT", None)

    @property
    def watermark(self) -> Optional[int]:
        """Beacon watermark (also known as customer or authorization id)."""
        return self.raw_settings.get("SETTING_WATERMARK", None)

    @property
    def is_trial(self) -> bool:
        """True if Beacon is a trial version (CRYPTO_TRIAL_PRODUCT). Otherwise, False."""
        return self.raw_settings.get("SETTING_CRYPTO_SCHEME") == CryptoScheme.CRYPTO_TRIAL_PRODUCT

    @property
    def version(self) -> BeaconVersion:
        """Deduced version of Cobalt Strike as :class:`~dissect.cobaltstrike.version.BeaconVersion` object.

        The version is deduced from the Beacon's :attr:`pe_export_stamp` when available and known,
        otherwise from :attr:`max_setting_enum`.
        """
        if self.pe_export_stamp:
            version = BeaconVersion.from_pe_export_stamp(self.pe_export_stamp)
            if version != "Unknown":
                return version
        return BeaconVersion.from_max_setting_enum(self.max_setting_enum)

    @property
    def public_key(self) -> bytes:
        """The RSA public key used by the Beacon in DER format."""
        return self.raw_settings.get("SETTING_PUBKEY", b"").rstrip(b"\x00")

    @property
    def sleeptime(self) -> Optional[int]:
        """The sleep time in milliseconds the Beacon uses between communication attempts."""
        return self.raw_settings.get("SETTING_SLEEPTIME", None)

    @property
    def jitter(self) -> Optional[int]:
        """The jitter in milliseconds the Beacon uses between communication attempts."""
        return self.raw_settings.get("SETTING_JITTER", None)


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input", metavar="FILE", nargs="+", help="Beacon to dump")
    parser.add_argument(
        "-x",
        "--xorkey",
        action="append",
        help="override default xor key(s) (default: -x 0x69 -x 0x2e -x 0x00)",
    )
    parser.add_argument(
        "--default-xor-keys-only",
        action="store_true",
        help="only try the default xor keys instead of all possible ones",
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["normal", "raw", "dumpstruct", "c2profile"],
        default="normal",
        help="output format",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="exit with non-zero code on error (default: continue processing other files)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbosity level (-v for INFO, -vv for DEBUG)",
    )
    return parser


@catch_sigpipe
def main():
    """Entrypoint for beacon-dump."""
    from dissect.cobaltstrike import c2profile, utils

    parser = build_parser()
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    xor_keys = None
    if args.xorkey:
        xor_keys = tuple(utils.pack_be(int(x, 0)) for x in args.xorkey)

    def iter_path(files: list[str]) -> Iterator[str]:
        """If `files` contains a directory, yield all files in the dir recursively. Otherwise, yield path as is."""
        for fname in files:
            if fname == "-":
                yield fname
            else:
                path = Path(fname)
                if path.is_file():
                    yield str(path)
                elif path.is_dir():
                    for f in path.rglob("*"):
                        if f.is_file():
                            yield str(f)
                else:
                    logging.warning("File not found: %r", fname)

    dumped = False
    for fname in iter_path(args.input):
        logging.info("Processing: %r", fname)
        try:
            if fname in ("-", "/dev/stdin"):
                with io.BytesIO(sys.stdin.buffer.read()) as fin:
                    config = BeaconConfig.from_file(fin, xor_keys=xor_keys, all_xor_keys=not args.default_xor_keys_only)
            else:
                config = BeaconConfig.from_path(fname, xor_keys=xor_keys, all_xor_keys=not args.default_xor_keys_only)
        except ValueError:
            print(f"{fname}: No beacon configuration found.", file=sys.stderr)
            if args.fail_on_error:
                return 1
            continue
        except Exception as e:
            print(f"{fname}: Error processing beacon configuration: {e}", file=sys.stderr)
            if args.verbose >= 1:
                import traceback

                traceback.print_exc()
            if args.fail_on_error:
                return 1
            continue

        dumped = True
        if args.type == "raw":
            for setting in config.settings_tuple:
                print(setting)

        elif args.type == "dumpstruct":
            cstruct.hexdump(config.config_block)
            print("-----")
            for setting in config.settings_tuple:
                cstruct.dumpstruct(setting)
                print("-" * 10)
        elif args.type == "normal":
            if args.verbose >= 1:
                for setting in config.settings_tuple:
                    if (stock_types := STOCK_TYPE.get(setting.index)) and setting.type not in stock_types:
                        logger.warning(f"Stock type mismatch for {setting.index}: {setting.type} not in {stock_types}")

            settings = config.settings
            for setting, value in settings.items():
                print(f"{setting} = {value!r}")
            if args.verbose >= 1:
                print("-" * 50)
                if config.pe_export_stamp:
                    print(
                        "pe_export_stamp = {}, {}, {} - {} - {}".format(
                            config.pe_export_stamp if config.pe_export_stamp else "N/A",
                            hex(config.pe_export_stamp) if config.pe_export_stamp else "N/A",
                            time.ctime(config.pe_export_stamp) if config.pe_export_stamp else "N/A",
                            config.version,
                            fname,
                        )
                    )
                else:
                    print("pe_export_stamp = None", config.version, fname)

                if config.pe_compile_stamp is not None:
                    print(
                        "pe_compile_stamp = {}, {}, {}, {}".format(
                            config.pe_compile_stamp,
                            hex(config.pe_compile_stamp),
                            time.ctime(config.pe_compile_stamp),
                            config.version,
                        )
                    )
                print(
                    "max_setting_enum = {} - {}".format(
                        config.max_setting_enum,
                        BeaconSetting(config.max_setting_enum),
                    )
                )
                print("settings_enums = {} - {}".format("-".join(map(str, config.setting_enums)), config.version))
                print(f"{config.domains} - beacon_version = {config.version}")
                if config.guardrails:
                    print("guardrail payload xor key =", config.guardrails.payload_xor_key)
                    print("guardrail options =", [s.option for s in config.guardrails.settings])
                print("stages =", config.stages)
        elif args.type == "c2profile":
            profile = c2profile.C2Profile.from_beacon_config(config)
            print(profile.as_text())

    return 0 if dumped else 1


if __name__ == "__main__":
    sys.exit(main())

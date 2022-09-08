"""
This module is responsible for extracting and parsing configuration from Cobalt Strike beacon payloads.
"""
import os
import io
import sys
import hashlib
import logging
import ipaddress
import itertools
import functools
from collections import OrderedDict
from types import MappingProxyType
from typing import Any, BinaryIO, Dict, Callable, Iterator, List, Mapping, Optional, Tuple, Union, cast

from dissect import cstruct

from dissect.cobaltstrike import pe
from dissect.cobaltstrike.version import BeaconVersion
from dissect.cobaltstrike.xordecode import XorEncodedFile
from dissect.cobaltstrike.utils import catch_sigpipe, p8, u16be, u32, u32be
from dissect.cobaltstrike.utils import xor, iter_find_needle

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
    SETTING_KILLDATE_YEAR = 16,
    SETTING_KILLDATE_MONTH = 17,
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
    // DEPRECATED_SETTING_INJECT_OPTIONS = 36,

    // Renamed from DEPRECATED_SETTING_INJECT_OPTIONS in CobaltStrike 4.5
    SETTING_WATERMARKHASH = 36,

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
    SETTING_PROCINJ_ALLOWED = 48,

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
};

enum DeprecatedBeaconSetting: uint16 {
    SETTING_KILLDATE_YEAR = 16,
    SETTING_INJECT_OPTIONS = 36,
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

enum InjectExecutor: uint8 {
    CreateThread = 1,
    SetThreadContext = 2,
    CreateRemoteThread = 3,
    RtlCreateUserThread = 4,
    NtQueueApcThread = 5,
    CreateThread_ = 6,
    CreateRemoteThread_ = 7,
    NtQueueApcThread_s = 8
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

DEFAULT_XOR_KEYS: List[bytes] = [b"\x69", b"\x2e", b"\x00"]
""" Default XOR keys used by Cobalt Strike for obfuscating Beacon config bytes """


def find_beacon_config_bytes(fh: BinaryIO, xorkey: bytes) -> Iterator[bytes]:
    r"""Find and yield (possible) Cobalt Strike configuration bytes from file `fh` using `xorkey` (eg: b"\x69").

    This is done by scraping the file `fh` for XOR encoded configuration blocks.
    A beacon configuration block always (unless modified) starts with::

       Setting(index=SETTING_PROTOCOL, type=TYPE_SHORT, length=0x2)

       # which translates to the following bytes
       b"\x00\x01\x00\x01\x00\x02\x00"

    These bytes are used in conjuction with the XOR key for finding the (potential) start of a configuration block.

    Args:
        fh: file object
        xorkey: XOR key (as bytes)

    Yields:
        Beacon configuration bytes (4096 bytes), in deobfuscated (un-XOR'd) form.
    """

    # This is the maximum size for the beacon config and is also padded as such
    PATCH_SIZE = 4096
    # This is the default Beacon config starting bytes (unless it's modified)
    CONFIG_HEADER = b"\x00\x01\x00\x01\x00\x02\x00"
    xorred_config_block = xor(CONFIG_HEADER, xorkey)

    for pos in iter_find_needle(fh, xorred_config_block, start_offset=0):
        fh.seek(pos)
        data = fh.read(PATCH_SIZE)
        logger.debug(f"Found CONFIG_HEADER using xorkey: 0x{xorkey.hex()}")
        yield xor(data, xorkey)


def iter_beacon_config_blocks(
    fobj: BinaryIO, xor_keys=None, xordecode=True, all_xor_keys=False
) -> Iterator[Tuple[bytes, dict]]:
    """Yield tuple with found Beacon `config_block_bytes` from file `fobj` and `extra_info` dict

    It always start seeking from the beginning of `fobj`. Side effects: file handle position due to seeking

    The `extra_info` dictionary holds some metadata such as if the `fobj` was xorencoded and which xorkey was used.

    Args:
        xor_keys: list XOR keys (as bytes), defaults to: :attr:`DEFAULT_XOR_KEYS` if not specified.
        xordecode: If ``True`` it will also try to `XorDecode` the file object.
        all_xor_keys: Try ALL single-byte XOR keys if no beacon config is found using the default keys.

    Yields:
        Tuple as ``(config_block_bytes, extra_info_dict)``
        -- `extra_info` dict contains: ``{"xorkey": bytes, "xorencoded": bool}``
    """
    found = False
    xor_keys = xor_keys or DEFAULT_XOR_KEYS
    logger.debug(f"xor_keys: {xor_keys!r}")

    # Try XorEncoded files first as they are more common
    if not found and xordecode:
        try:
            fxor = cast(BinaryIO, XorEncodedFile.from_file(fobj))
            for xorkey in xor_keys:
                for config_block in find_beacon_config_bytes(fxor, xorkey):
                    found = True
                    yield config_block, {"xorkey": xorkey, "xorencoded": True}
        except ValueError:
            pass

    # Try finding config block without XorEncoding
    if not found:
        for xorkey in xor_keys:
            for config_block in find_beacon_config_bytes(fobj, xorkey):
                found = True
                yield config_block, {"xorkey": xorkey, "xorencoded": False}

    # Retry with left over xor keys if specified
    if not found and all_xor_keys:
        logger.debug("config_block not found, trying all xor keys...")
        left_xor_keys = make_byte_list(exclude=xor_keys)
        logger.debug(f"left xor keys to try: {left_xor_keys}")
        yield from iter_beacon_config_blocks(fobj, left_xor_keys, xordecode=xordecode, all_xor_keys=False)


def make_byte_list(exclude: List[bytes] = None) -> List[bytes]:
    """Return all single-byte bytes as an ordered list, excluding `exclude` bytes."""
    return sorted({p8(x) for x in range(256)} - set(exclude or []))


def iter_settings(fobj: Union[bytes, BinaryIO]) -> Iterator["Setting"]:
    """Returns an iterator yielding :class:`Setting` objects by reading data from `fobj`

    The file position will be at the end of the Beacon config after parsing is done.
    This can be used to determine the exact size of the Beacon configuration block.

    Some edge cases are also handled:

     - User-Agent string that exceeds the Setting length.
     - Deprecated setting SETTING_INJECT_OPTIONS

    Args:
        fobj: bytes or file-like object with Beacon configuration data

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
        if setting.index == BeaconSetting.SETTING_USERAGENT:
            # Handle cases where User-Agent is too long in some configs
            # eg: fcece52fd030ca66043ae29af2116a79
            if setting.length == 0x80:
                if len(setting.value.rstrip(b"\x00")) >= 0x80:
                    while True:
                        x = fobj.read(1)
                        if x == b"\x00":
                            fobj.seek(-1, io.SEEK_CUR)
                            break
                        setting.value += x
        elif setting.index == BeaconSetting.SETTING_WATERMARKHASH:
            # Handle deprecated setting INJECT_OPTIONS -> WATERMARKHASH
            # We can identify the difference using TYPE_SHORT vs TYPE_PTR.
            if setting.type == SettingsType.TYPE_SHORT:
                setting.index = DeprecatedBeaconSetting.SETTING_INJECT_OPTIONS

        yield setting


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)


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
            pass
    return rsteps


def parse_transform_binary(program: bytes, build: str = "metadata") -> List[Tuple[str, Union[str, bytes, bool]]]:
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
    p = io.BytesIO(program)
    while True:
        d = p.read(4)
        value = u32be(d)
        if len(d) != 4 or value == 0:
            break
        name = TransformStep.reverse.get(value, "")
        step = getattr(TransformStep, name, None)
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
        if inject in (InjectExecutor.CreateThread_, InjectExecutor.CreateRemoteThread_):
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
    return null_terminated_bytes(data).decode("ascii", "ignore")


SETTING_TO_PRETTYFUNC: Dict[BeaconSetting, Callable] = {
    BeaconSetting.SETTING_PROCINJ_STUB: lambda x: x.hex(),
    BeaconSetting.SETTING_SPAWNTO: lambda x: x.hex(),
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
    BeaconSetting.SETTING_MASKED_WATERMARK: lambda x: x.hex()
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
        self.settings_tuple = tuple(iter_settings(config_block))
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

        # Used for caching
        self._settings: Optional[Mapping[str, Any]] = None
        self._settings_by_index: Optional[Mapping[int, Any]] = None
        self._raw_settings: Optional[Mapping[str, Any]] = None
        self._raw_settings_by_index: Optional[Mapping[int, Any]] = None

    @classmethod
    def from_file(cls, fobj: BinaryIO, xor_keys: List[bytes] = None, all_xor_keys: bool = False) -> "BeaconConfig":
        """Create a :class:`BeaconConfig` from file object, or raises ValueError if no beacon config is found.

        Args:
            fobj: file-like object
            xor_keys: override the default `XOR` keys (as bytes) when specified. Default ``None``.
            all_xor_keys: if ``True``, it will try ALL single-byte `XOR` keys if the defaults don't work

        Returns:
            :class:`BeaconConfig`

        Raises:
            ValueError: If no valid beacon configuration was found
        """
        for config_block, extra_info in iter_beacon_config_blocks(fobj, xor_keys=xor_keys, all_xor_keys=all_xor_keys):
            bconfig = cls(config_block)
            # Set extra metadata
            bconfig.xorkey = extra_info["xorkey"]
            bconfig.xorencoded = extra_info["xorencoded"]
            # Try to extract some PE artifacts
            try:
                fh = XorEncodedFile.from_file(fobj) if bconfig.xorencoded else fobj
            except ValueError:
                fh = fobj
            bconfig.pe_compile_stamp, bconfig.pe_export_stamp = pe.find_compile_stamps(fh)
            bconfig.architecture = pe.find_architecture(fh)
            # Return the first found beacon config.
            return bconfig
        raise ValueError("No valid Beacon configuration found")

    @classmethod
    def from_path(
        cls,
        path: Union[str, os.PathLike],
        xor_keys: List[bytes] = None,
        all_xor_keys: bool = False,
    ) -> "BeaconConfig":
        """Create a :class:`BeaconConfig` from path, or raises ValueError if no beacon config is found.

        Args:
            path: path to file on disk
            xor_keys: override the default `XOR` keys (as bytes) when specified. Default ``None``.
            all_xor_keys: if ``True`` it will try ALL single-byte `XOR` keys if the defaults don't work

        Returns:
            :class:`BeaconConfig`

        Raises:
            ValueError: If no valid beacon configuration was found
        """
        with open(path, "rb") as fobj:
            return cls.from_file(fobj, xor_keys=xor_keys, all_xor_keys=all_xor_keys)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        xor_keys: List[bytes] = None,
        all_xor_keys: bool = False,
    ) -> "BeaconConfig":
        """Create a :class:`BeaconConfig` from bytes, or raises ValueError if no beacon config is found.

        Args:
            data: configuration bytes
            xor_keys: override the default `XOR` keys when specified. Default ``None``.
            all_xor_keys: if ``True`` it will try ALL single-byte `XOR` keys if the defaults don't work

        Returns:
            :class:`BeaconConfig`

        Raises:
            ValueError: If no valid beacon configuration was found
        """
        return cls.from_file(io.BytesIO(data), xor_keys=xor_keys, all_xor_keys=all_xor_keys)

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
        return max(self.setting_enums)

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
                key = setting.index.name
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

        The version is deduced from the Beacon's :attr:`pe_export_stamp` when available,
        otherwise from :attr:`max_setting_enum`.
        """
        if self.pe_export_stamp:
            return BeaconVersion.from_pe_export_stamp(self.pe_export_stamp)
        return BeaconVersion.from_max_setting_enum(self.max_setting_enum)


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input", metavar="FILE", help="Beacon to dump")
    parser.add_argument(
        "-x",
        "--xorkey",
        action="append",
        help="override default xor key(s) (default: -x 0x69 -x 0x2e -x 0x00)",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="try all other single byte xor keys when default ones fail",
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["normal", "raw", "dumpstruct", "c2profile"],
        default="normal",
        help="output format",
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
    from . import c2profile
    from . import utils

    parser = build_parser()
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(
        level=level,
        datefmt="[%X]",
        format="%(asctime)s %(name)s %(message)s",
    )

    xor_keys = None
    if args.xorkey:
        xor_keys = tuple(utils.pack_be(int(x, 0)) for x in args.xorkey)

    try:
        if args.input in ("-", "/dev/stdin"):
            with io.BytesIO(sys.stdin.buffer.read()) as fin:
                config = BeaconConfig.from_file(fin, xor_keys=xor_keys, all_xor_keys=args.all)
        else:
            config = BeaconConfig.from_path(args.input, xor_keys=xor_keys, all_xor_keys=args.all)
    except ValueError:
        print(f"{args.input}: No beacon configuration found.", file=sys.stderr)
        return 1

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
        settings = config.settings
        for setting, value in settings.items():
            print(f"{setting} = {value!r}")
    elif args.type == "c2profile":
        profile = c2profile.C2Profile.from_beacon_config(config)
        print(profile.as_text())


if __name__ == "__main__":
    sys.exit(main())

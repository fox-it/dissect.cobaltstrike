"""
This module is responsible for parsing and generating Cobalt Strike Malleable C2 profiles.
It uses the `lark-parser` library for parsing the syntax using the ``c2profile.lark`` grammar file.
"""
import os
import sys
import logging
import collections
from typing import Any, List, Tuple, Union

from lark import Lark, Tree, Token
from lark.reconstruct import Reconstructor

from dissect.cobaltstrike.beacon import BeaconConfig, BeaconSetting
from dissect.cobaltstrike.utils import catch_sigpipe

logger = logging.getLogger(__name__)

c2profile_parser = Lark.open("c2profile.lark", parser="lalr", rel_to=__file__, maybe_placeholders=False)


def value_to_string(value: Union[str, bytes]) -> str:
    """Converts value to it's STRING Token value"""
    if isinstance(value, bytes):
        # we prepend a double quote to the bytes so repr() always escapes using single quote and strip it afterwards
        value = repr(b'"' + value)[3:-1]
    if isinstance(value, str):
        # we escape double quotes, because we return it as a double quoted string value
        value = value.replace('"', '\\"')
        # we don't have to escape single quotes, as we return it as a double quoted value
        value = value.replace("\\'", "'")
    return f'"{value}"'


def string_token_to_bytes(token: Token) -> Union[Token, bytes]:
    """Convert a STRING Token value to it's native Python bytes value.

    If the input is not of Token.type STRING it will return the original Token.
    """
    if isinstance(token, Token) and token.type == "STRING":
        # strip the surrounding double quotes
        bstring = token.value[1:-1]
        buffer = []
        # logger.debug(bstring)
        it = StringIterator(bstring)
        for c in it:
            if c == "\\" and it.has_next():
                next2 = next(it)
                if next2 == "u":
                    if not it.has_next(4):
                        raise ValueError("not enough remaining chars for \\uXXXX")
                    _ = it.next(2)
                    hexstr = "".join(it.next(2))
                    buffer.append(int(hexstr, 16))
                elif next2 == "x":
                    if not it.has_next(2):
                        raise ValueError("not enough remaining chars for \\xXX")
                    hexstr = "".join(it.next(2))
                    buffer.append(int(hexstr, 16))
                elif next2 == "n":
                    buffer.append(ord("\n"))
                elif next2 == "r":
                    buffer.append(ord("\r"))
                elif next2 == "t":
                    buffer.append(ord("\t"))
                elif next2 == "\\":
                    buffer.append(ord("\\"))
                elif next2 == '"':
                    buffer.append(ord('"'))
                elif next2 == "'":
                    buffer.append(ord("'"))
            else:
                buffer.append(ord(c))
        # logger.debug(f"DEBUG: {bytes(buffer)}")
        return bytes(buffer)
    return token


class StringIterator:
    """Helper class for iterating over characters in a string"""

    def __init__(self, string: str) -> None:
        self.buffer: List[str] = [chr(ord(c) & 0xFF) for c in string]
        self.index: int = 0

    def has_next(self, count: int = 1) -> bool:
        return self.index + count <= len(self.buffer)

    def next(self, count: int) -> List[str]:
        c = self.buffer[self.index : self.index + count]
        self.index += count
        return c

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        if self.index < len(self.buffer):
            c = self.buffer[self.index]
            self.index += 1
            return c
        raise StopIteration


class ConfigBlock:
    """Base class for configuration blocks"""

    __name__ = "ConfigBlock"

    def __init__(self, **kwargs):
        #: The AST tree
        self.tree = Tree(self.__name__, [])
        self.init_kwargs(**kwargs)

    def init_kwargs(self, **kwargs):
        for option, value in kwargs.items():
            func = getattr(self, option, None)
            if callable(func):
                func(option, value)
            elif isinstance(value, ConfigBlock):
                self.set_config_block(option, value)
            else:
                self.set_option(option, value)

    def set_config_block(self, option, config_block):
        self.tree.children.append(Tree(option, config_block.tree.children))

    def set_non_empty_config_block(self, option, config_block):
        if config_block.tree.children:
            self.set_config_block(option, config_block)

    def set_option(self, option, value):
        value = value_to_string(value)
        self.tree.children.append(
            Tree(
                option,
                [
                    Tree("string", [Token("STRING", value)]),
                ],
            )
        )

    def _pair(self, option, value):
        for a, b in value:
            a = value_to_string(a)
            b = value_to_string(b)
            self.tree.children.append(
                Tree(
                    option,
                    [
                        Tree("string", [Token("STRING", a)]),
                        Tree("string", [Token("STRING", b)]),
                    ],
                )
            )

    def _enable(self, option, value):
        self.tree.children.append(Tree(option, []))

    def _header(self, option, value):
        for header_name, header_val in value:
            header_name = value_to_string(header_name)
            header_val = value_to_string(header_val)
            self.tree.children.append(
                Tree(
                    "header",
                    [
                        Tree("string", [Token("STRING", header_name)]),
                        Tree("string", [Token("STRING", header_val)]),
                    ],
                )
            )

    def _parameter(self, option, value):
        for param, val in value:
            param = value_to_string(param)
            val = value_to_string(val)
            self.tree.children.append(
                Tree(
                    "parameter",
                    [
                        Tree("string", [Token("STRING", param)]),
                        Tree("string", [Token("STRING", val)]),
                    ],
                )
            )


class HttpOptionsBlock(ConfigBlock):
    """`.http-{stager,get,post}.{client,server}` block"""

    __name__ = "http_options"
    header = ConfigBlock._pair
    parameter = ConfigBlock._pair


class DataTransformBlock(ConfigBlock):
    """data_transform block"""

    __name__ = "DataTransformBlock"

    @property
    def tree(self):
        return Tree(
            self.__name__,
            [
                Tree(
                    "data_transform",
                    [
                        Tree("steps", self.steps),
                        Tree("termination", self.termination),
                    ],
                )
            ],
        )

    def __init__(self, steps=None):
        self.steps = []
        self.termination = []

        steps = steps or []
        for option in steps:
            if option in ("base64", "base64url", "mask", "netbios", "netbiosu"):
                self.add_step(option, None)
            elif option in ("print", "uri-append", "uri_append"):
                self.add_termination(option.replace("-", "_"), None)
            elif len(option) == 2:
                option, value = option
                if option in ("header", "parameter"):
                    self.add_termination(option, value)
                else:
                    self.add_step(option, value)

    def add_step(self, option, value):
        val = []
        if value is not None:
            val.append(Tree("string", [Token("STRING", value_to_string(value))]))
        self.steps.append(Tree(option, val))

    def add_termination(self, option, value):
        val = []
        if value is not None:
            val.append(Tree("string", [Token("STRING", value_to_string(value))]))
        self.termination.append(Tree(option, val))


class HttpStagerBlock(ConfigBlock):
    """`.http-stager` block"""

    __name__ = "http_stager"


class HttpConfigBlock(ConfigBlock):
    """`.http-config` block"""

    __name__ = "http_config"
    header = ConfigBlock._header


class StageBlock(ConfigBlock):
    """`.stage` block"""

    __name__ = "stage"


class StageTransformBlock(ConfigBlock):
    """`.stage.transform-x86` and `.stage.transform-x64` block"""

    __name__ = "StageTransformBlock"

    strrep = ConfigBlock._pair


class ProcessInjectBlock(ConfigBlock):
    """`.process-inject` block"""

    __name__ = "process_inject"


class HttpGetBlock(ConfigBlock):
    """`.http-get` block"""

    __name__ = "http_get"


class HttpPostBlock(ConfigBlock):
    """`.http-post` block"""

    __name__ = "http_post"


class PostExBlock(ConfigBlock):
    """`.post-ex` block"""

    __name__ = "post_ex"


class DnsBeaconBlock(ConfigBlock):
    """`.dns-beacon` block"""

    __name__ = "dns_beacon"


class ExecuteOptionsBlock(ConfigBlock):
    """`.process-inject.execute` block"""

    __name__ = "ExecuteOptionsBlock"

    createthread_special = ConfigBlock.set_option
    createremotethread_special = ConfigBlock.set_option
    createthread = ConfigBlock._enable
    createremotethread = ConfigBlock._enable
    ntqueueapcthread = ConfigBlock._enable
    ntqueueapcthread_s = ConfigBlock._enable
    rtlcreateuserthread = ConfigBlock._enable
    setthreadcontext = ConfigBlock._enable

    @classmethod
    def from_execute_list(cls, execute_list=None):
        block = cls()
        for option in execute_list:
            if isinstance(option, (list, tuple)):
                option, value = option
                if option == "CreateThread":
                    block.set_option("createthread_special", value)
                elif option == "CreateRemoteThread":
                    block.set_option("createremotethread_special", value)
                else:
                    raise ValueError(f"Unknown option: {option}")
            else:
                if option in [
                    "CreateThread",
                    "SetThreadContext",
                    "CreateRemoteThread",
                    "NtQueueApcThread",
                    "NtQueueApcThread-s",
                    "RtlCreateUserThread",
                ]:
                    block._enable(option.lower().replace("-", "_"), True)
                else:
                    raise ValueError(f"Unknown option: {option}")
        return block


class C2Profile(ConfigBlock):
    """A :class:`C2Profile` object represents a parsed Malleable C2 Profile

    Besides loading C2 Profiles, it also provides methods for building a C2 Profile from scratch.
    """

    __name__ = "start"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._dict_cache = {}
        self._dict_hash = None

    def set_option(self, option, value):
        """Sets a global option in the AST tree. E.g: ``set_option("jitter", "6000")``"""
        value = value_to_string(value)
        self.tree.children.append(
            Tree(
                "option",
                [
                    Token("OPTION", option),
                    Tree("string", [Token("STRING", value)]),
                ],
            )
        )

    @classmethod
    def from_path(cls, path: Union[str, os.PathLike]) -> "C2Profile":
        """Construct a :class:`C2Profile` from given path (path to a malleable C2 profile)"""
        with open(path, "r") as f:
            return cls.from_text(f.read())

    @classmethod
    def from_text(cls, source: str) -> "C2Profile":
        """Construct a :class:`C2Profile` from text (malleable C2 profile syntax)"""
        profile = cls()
        profile.tree = c2profile_parser.parse(source)
        return profile

    @classmethod
    def from_beacon_config(cls, config: BeaconConfig) -> "C2Profile":
        """Construct a :class:`C2Profile` from a :class:`~dissect.cobaltstrike.beacon.BeaconConfig`"""
        profile = cls()
        http_get = HttpGetBlock()
        http_post = HttpPostBlock()
        stage = StageBlock()

        c2_recover: List[Union[Tuple[str, Any], str]] = []
        http_get_client = HttpOptionsBlock()
        http_post_client = HttpOptionsBlock()
        proc_inj = ProcessInjectBlock()
        dns_beacon = DnsBeaconBlock()
        # http_get_server = HttpOptionsBlock()

        for setting, value in config.settings_by_index.items():
            logger.debug(f"{setting} -> {value}")
            if setting == BeaconSetting.SETTING_SLEEPTIME:
                profile.set_option("sleeptime", value)
            elif setting == BeaconSetting.SETTING_MAXGET:
                # determined by .http-get.server.output", 1048576
                pass
            elif setting == BeaconSetting.SETTING_JITTER:
                profile.set_option("jitter", value)
            elif setting == BeaconSetting.SETTING_DOMAINS:
                uris = ", ".join(config.uris)
                http_get.set_option("uri", uris)
            elif setting == BeaconSetting.SETTING_SPAWNTO:
                # profile.set_option("spawnto", value)
                # deprecated
                pass
            elif setting == BeaconSetting.SETTING_SPAWNTO_X86:
                profile.set_option("spawnto_x86", value)
            elif setting == BeaconSetting.SETTING_SPAWNTO_X64:
                profile.set_option("spawnto_x64", value)
            elif setting == BeaconSetting.SETTING_C2_VERB_GET:
                http_get.set_option("verb", value)
            elif setting == BeaconSetting.SETTING_C2_VERB_POST:
                http_post.set_option("verb", value)
            elif setting == BeaconSetting.SETTING_C2_CHUNK_POST:
                # public boolean shouldChunkPosts()
                # return !this.posts(".http-post.client.output");
                pass
            elif setting == BeaconSetting.SETTING_CLEANUP:
                stage.set_option("cleanup", value)
            elif setting == BeaconSetting.SETTING_CFG_CAUTION:
                pass
            elif setting == BeaconSetting.SETTING_USERAGENT:
                profile.set_option("useragent", value)
            elif setting == BeaconSetting.SETTING_SUBMITURI:
                http_post.set_option("uri", value)
            elif setting == BeaconSetting.SETTING_C2_RECOVER:
                c2_recover = []
                for k, v in value:
                    if v is True:
                        c2_recover.append(k)
                    elif isinstance(v, int):
                        c2_recover.append((k, "X" * v))
                    else:
                        c2_recover.append((k, v))
            elif setting == BeaconSetting.SETTING_C2_REQUEST:
                # .http-get.client
                _build = None
                headers = []
                params = []
                block_steps = collections.defaultdict(list)
                for k, v in value:
                    if k in ("_HEADER", "_HOSTHEADER"):
                        v = v.decode()
                        header, _, header_val = v.partition(": ")
                        headers.append((header, header_val))
                    elif k == "_PARAMETER":
                        v = v.decode()
                        param, _, param_val = v.partition("=")
                        params.append((param, param_val))
                    elif k == "BUILD":
                        _build = v
                    elif v is True:
                        block_steps[_build].append(k.lower())
                    else:
                        block_steps[_build].append((k.lower(), v.decode()))
                logger.debug(f"block_steps: {block_steps}")
                if headers:
                    http_get_client._pair("header", headers)
                if params:
                    http_get_client._pair("parameter", params)
                for block, steps in block_steps.items():
                    http_get_client.set_config_block(block, DataTransformBlock(steps=steps))

            elif setting == BeaconSetting.SETTING_C2_POSTREQ:
                # .http-post.client
                _build = None
                headers = []
                params = []
                block_steps = collections.defaultdict(list)
                for k, v in value:
                    if k in ("_HEADER", "_HOSTHEADER"):
                        v = v.decode()
                        header, _, header_val = v.partition(": ")
                        headers.append((header, header_val))
                    elif k == "_PARAMETER":
                        v = v.decode()
                        param, _, param_val = v.partition("=")
                        params.append((param, param_val))
                    elif k == "BUILD":
                        _build = v
                    elif v is True:
                        block_steps[_build].append(k.lower())
                    else:
                        # log.debug(f"{k} -> {v}")
                        v = repr(v)[2:-1]
                        block_steps[_build].append((k.lower(), v))
                logger.debug(f"block_steps: {block_steps}")
                if headers:
                    http_post_client._pair("header", headers)
                if params:
                    http_post_client._pair("parameter", params)
                for block, steps in block_steps.items():
                    http_post_client.set_config_block(block, DataTransformBlock(steps=steps))
            elif setting == BeaconSetting.SETTING_HOST_HEADER:
                pass
            elif setting == BeaconSetting.SETTING_HTTP_NO_COOKIES:
                pass
            elif setting == BeaconSetting.SETTING_PROXY_BEHAVIOR:
                pass
            elif setting == BeaconSetting.SETTING_TCP_FRAME_HEADER and value:
                profile.set_option("tcp_frame_header", repr(value)[2:-1])
            elif setting == BeaconSetting.SETTING_SMB_FRAME_HEADER and value:
                profile.set_option("smb_frame_header", repr(value)[2:-1])
            elif setting == BeaconSetting.SETTING_EXIT_FUNK:
                pass
            elif setting == BeaconSetting.SETTING_KILLDATE:
                pass
            elif setting == BeaconSetting.SETTING_GARGLE_NOOK and value:
                stage.set_option("sleep_mask", value)
            elif setting == BeaconSetting.SETTING_PROCINJ_PERMS_I:
                if value == 64:
                    proc_inj.set_option("startrwx", "true")
                elif value == 4:
                    proc_inj.set_option("startrwx", "false")
            elif setting == BeaconSetting.SETTING_PROCINJ_PERMS:
                if value == 64:
                    proc_inj.set_option("userwx", "true")
                elif value == 32:
                    proc_inj.set_option("userwx", "false")
            elif setting == BeaconSetting.SETTING_PROCINJ_MINALLOC and value:
                proc_inj.set_option("min_alloc", value)
            elif setting == BeaconSetting.SETTING_PROCINJ_TRANSFORM_X86:
                steps = []
                prepend = ""
                append = ""
                for k, v in value:
                    # v = v.decode()
                    v = repr(v)[2:-1]
                    if k == "prepend":
                        prepend = v
                    elif k == "append":
                        append = v
                transform_block = StageTransformBlock()
                if prepend:
                    transform_block.set_option("prepend", prepend)
                if append:
                    transform_block.set_option("append", append)
                if prepend or append:
                    proc_inj.set_config_block("transform_x86", transform_block)
            elif setting == BeaconSetting.SETTING_PROCINJ_TRANSFORM_X64:
                steps = []
                # proc_inj.set_config_block("transform_x64", DataTransformBlock(steps=steps))
                prepend = ""
                append = ""
                for k, v in value:
                    v = repr(v)[2:-1]
                    if k == "prepend":
                        prepend = v
                    elif k == "append":
                        append = v
                transform_block = StageTransformBlock()
                if prepend:
                    transform_block.set_option("prepend", prepend)
                if append:
                    transform_block.set_option("append", append)
                if prepend or append:
                    proc_inj.set_config_block("transform_x64", transform_block)
            elif setting == BeaconSetting.SETTING_PROCINJ_STUB:
                pass
            elif setting == BeaconSetting.SETTING_PROCINJ_EXECUTE:
                exec_options = ExecuteOptionsBlock()
                for item in value:
                    if " " in item:
                        option, _, val = item.partition(" ")
                        val = val[1:-1]
                        if option == "CreateThread":
                            exec_options.set_option("createthread_special", val)
                        elif option == "CreateRemoteThread":
                            exec_options.set_option("createremotethread_special", val)
                    if item in [
                        "CreateThread",
                        "SetThreadContext",
                        "CreateRemoteThread",
                        "NtQueueApcThread",
                        "NtQueueApcThread-s",
                        "RtlCreateUserThread",
                    ]:
                        exec_options._enable(item.lower().replace("-", "_"), True)
                if value:
                    proc_inj.set_config_block("execute", exec_options)
            elif setting == BeaconSetting.SETTING_PROCINJ_ALLOCATOR:
                proc_inj.set_option("allocator", "NtMapViewOfSection" if value else "VirtualAllocEx")
            elif setting == BeaconSetting.SETTING_DNS_BEACON_BEACON:
                dns_beacon.set_option("beacon", value)
            elif setting == BeaconSetting.SETTING_DNS_BEACON_GET_A:
                dns_beacon.set_option("get_a", value)
            elif setting == BeaconSetting.SETTING_DNS_BEACON_GET_AAAA:
                dns_beacon.set_option("get_aaaa", value)
            elif setting == BeaconSetting.SETTING_DNS_BEACON_GET_TXT:
                dns_beacon.set_option("get_txt", value)
            elif setting == BeaconSetting.SETTING_DNS_BEACON_PUT_METADATA:
                dns_beacon.set_option("put_metadata", value)
            elif setting == BeaconSetting.SETTING_DNS_BEACON_PUT_OUTPUT:
                dns_beacon.set_option("put_output", value)
            elif setting == BeaconSetting.SETTING_DNSRESOLVER and value:
                # this is not a c2profile setting, but a DNS Listener configuration option
                dns_beacon.set_option("comment_dns_resolver", value)
            elif setting == BeaconSetting.SETTING_DNS_IDLE:
                dns_beacon.set_option("dns_idle", value)
            elif setting == BeaconSetting.SETTING_DNS_SLEEP:
                dns_beacon.set_option("dns_sleep", value)
            elif setting == BeaconSetting.SETTING_MAXDNS:
                dns_beacon.set_option("maxdns", value)

        if c2_recover:
            http_get.set_non_empty_config_block("server", HttpOptionsBlock(output=DataTransformBlock(steps=c2_recover)))
        http_get.set_non_empty_config_block("client", http_get_client)
        profile.set_non_empty_config_block("http_get", http_get)
        http_post.set_non_empty_config_block("client", http_post_client)
        profile.set_non_empty_config_block("http_post", http_post)
        profile.set_non_empty_config_block("stage", stage)
        profile.set_non_empty_config_block("process_inject", proc_inj)
        profile.set_non_empty_config_block("dns_beacon", dns_beacon)
        return profile

    def __str__(self) -> str:
        return self.as_text()

    def as_text(self) -> str:
        """Return the C2 Profile settings as text (malleable C2 profile syntax)."""

        def postproc(items):
            line = []
            indent = 0
            for item in items:
                line.append(item)
                if item in "{};":
                    if "}" in line:
                        indent -= 1
                    if "{" in line:
                        yield "\n"
                    yield " " * 4 * indent
                    for i, x in enumerate(line):
                        yield x
                        if len(line) > i + 1 and line[i + 1] != ";":
                            yield " "
                    yield "\n"
                    if "{" in line:
                        indent += 1
                    line = []

        return Reconstructor(c2profile_parser).reconstruct(self.tree, postproc)

    def as_dict(self) -> dict:
        """Return the C2 Profile settings as a dictionary"""
        if self._dict_hash == hash(self.tree):
            return self._dict_cache
        line = []
        stack = []
        list_props = [
            "stage.transform-x86.header",
            "process-inject.transform-x86",
            "process-inject.execute",
            "http-post.server.output",
            "http-post.client.id",
            "http-post.client.output",
            "http-stager.server.output",
            "http-get.client.metadata",
            "http-get.server.output",
        ]
        items = Reconstructor(c2profile_parser)._reconstruct(self.tree)
        properties = collections.defaultdict(list)
        for item in items:
            if item == "set":
                continue
            line.append(item)
            if item in "{};":
                if item == "{":
                    line.pop()  # pop '{'
                    x = line[-1]
                    if isinstance(x, Token) and x == '"default"':
                        # handle "default" variant as default.
                        line.pop()
                    stack.extend(line)
                    # stack.append(line[-2])
                elif item == "}":
                    x = stack.pop()
                    if isinstance(x, Token):
                        # pop variant token
                        stack.pop()
                elif item == ";":
                    logger.debug(repr(line))
                    line.pop()  # pop ;
                    key = ".".join(stack)
                    if key in list_props:
                        value = tuple(string_token_to_bytes(x) for x in line)
                        if len(value) == 1:
                            value = value[0]
                        line = []
                    elif len(line) > 2:
                        value = []
                        for x in line[-2:]:
                            if x.type == "STRING":
                                value.append(str(x)[1:-1])
                            else:
                                value.append(x)
                        value = tuple(value)
                        line = line[:-2]
                    else:
                        value = line.pop()
                    key = ".".join(stack + line)
                    if isinstance(value, Token):
                        if value.type == "STRING":
                            # strip quotes
                            value = str(value)[1:-1]
                    properties[key].append(value)
                line = []
        self._dict_hash = hash(self.tree)
        self._dict_cache = dict(properties)
        return self._dict_cache

    @property
    def properties(self):
        """C2 Profile settings as dictionary, alias for :func:`~dissect.cobaltstrike.c2profile.C2Profile.as_dict`"""
        return self.as_dict()


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input", metavar="FILE", help="c2 profile or beacon to dump")
    parser.add_argument(
        "-b",
        "--beacon",
        action="store_true",
        help="input is a beacon instead of a .profile file",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="when using --beacon, try all xor keys when default ones fail",
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["pretty", "ast", "c2profile", "properties"],
        default="pretty",
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
    """Entrypoint for c2profile-dump."""

    import logging
    from dissect.cobaltstrike.beacon import BeaconConfig

    parser = build_parser()
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(
        level=level,
        datefmt="[%X]",
        format="%(asctime)s %(name)s %(message)s",
    )

    path = args.input
    if args.beacon:
        config = BeaconConfig.from_path(path, all_xor_keys=args.all)
        if not config:
            return f"BeaconConfig not found for {path!r}"
        profile = C2Profile.from_beacon_config(config)
    else:
        try:
            with open(args.input) as f:
                profile = C2Profile.from_text(f.read())
        except Exception as e:
            logging.exception(f"Failed to parse {path}: {e}", exc_info=False)
            return 1

    if args.type == "pretty":
        print(profile.tree.pretty())
    elif args.type == "ast":
        print(profile.tree)
    elif args.type == "c2profile":
        print(profile.as_text())
    elif args.type == "properties":
        for key, value in profile.properties.items():
            print(key, value)


if __name__ == "__main__":
    sys.exit(main())

"""
Beacon client that can actively connect to a Cobalt Strike Team Server.

.. danger::

   The client actively connects to a Cobalt Strike Team Server, caution should be taken when using this.
   A default client will perform check-ins and only log the tasks it receives unless implemented otherwise.

"""
# Python imports
import sys
import time
import random
import hashlib
import string
import urllib.parse
import reprlib
import inspect
import argparse
import datetime
import ipaddress
import logging

# Typing imports
from typing import Union, Optional, Tuple, Any, Dict, List, Callable

# Third party imports
try:
    import httpx
except ImportError:
    raise ImportError("httpx is required for the HTTP beacon client, install it with `pip install httpx`")

try:
    from flow.record import RecordWriter
except ImportError:
    raise ImportError(
        "flow.record is required for writing Beacon records, please install it with `pip install flow.record`"
    )

# Local imports
from dissect.cobaltstrike.c2 import (
    BeaconConfig,
    C2Data,
    ClientC2Data,
    C2Http,
    HttpRequest,
    HttpResponse,
    BeaconMetadata,
    c2packet_to_record,
)
from dissect.cobaltstrike.c2 import TaskPacket, CallbackPacket, BeaconCommand, BeaconCallback
from dissect.cobaltstrike.c2 import encrypt_metadata, encrypt_packet
from dissect.cobaltstrike.utils import catch_sigpipe, p32be, p32, enable_reprlib_flow_record

logger = logging.getLogger(__name__)
reprlib.aRepr.maxstring = 100
reprlib.aRepr.maxother = 100


# Source: https://github.com/fivethirtyeight/data/tree/master/most-common-name
# fmt: off
FIRST_NAMES = ["Michael", "James", "John", "Robert", "David", "William", "Mary", "Christopher", "Joseph", "Richard", "Daniel", "Thomas", "Matthew", "Jennifer", "Charles", "Anthony", "Patricia", "Linda", "Mark", "Elizabeth", "Joshua", "Steven", "Andrew", "Kevin", "Brian", "Barbara", "Jessica", "Jason", "Susan", "Timothy", "Paul", "Kenneth", "Lisa", "Ryan", "Sarah", "Karen", "Jeffrey", "Donald", "Ashley", "Eric", "Jacob", "Nicholas", "Jonathan", "Ronald", "Michelle", "Kimberly", "Nancy", "Justin", "Sandra", "Amanda", "Brandon", "Stephanie", "Emily", "Melissa", "Gary", "Edward", "Stephen", "Scott", "George", "Donna", "Jose", "Rebecca", "Deborah", "Laura", "Cynthia", "Carol", "Amy", "Margaret", "Gregory", "Sharon", "Larry", "Angela", "Maria", "Alexander", "Benjamin", "Nicole", "Kathleen", "Patrick", "Samantha", "Tyler", "Samuel", "Betty", "Brenda", "Pamela", "Aaron", "Kelly", "Heather", "Rachel", "Adam", "Christine", "Zachary", "Debra", "Katherine", "Dennis", "Nathan", "Christina", "Julie", "Jordan", "Kyle", "Anna"]  # noqa: E501
LAST_NAMES = ["SMITH", "JOHNSON", "WILLIAMS", "BROWN", "JONES", "GARCIA", "RODRIGUEZ", "MILLER", "MARTINEZ", "DAVIS", "HERNANDEZ", "LOPEZ", "GONZALEZ", "WILSON", "ANDERSON", "THOMAS", "TAYLOR", "LEE", "MOORE", "JACKSON", "PEREZ", "MARTIN", "THOMPSON", "WHITE", "SANCHEZ", "HARRIS", "RAMIREZ", "CLARK", "LEWIS", "ROBINSON", "WALKER", "YOUNG", "HALL", "ALLEN", "TORRES", "NGUYEN", "WRIGHT", "FLORES", "KING", "SCOTT", "RIVERA", "GREEN", "HILL", "ADAMS", "BAKER", "NELSON", "MITCHELL", "CAMPBELL", "GOMEZ", "CARTER", "ROBERTS", "DIAZ", "PHILLIPS", "EVANS", "TURNER", "REYES", "CRUZ", "PARKER", "EDWARDS", "COLLINS", "STEWART", "MORRIS", "MORALES", "ORTIZ", "GUTIERREZ", "MURPHY", "ROGERS", "COOK", "KIM", "MORGAN", "COOPER", "RAMOS", "PETERSON", "GONZALES", "BELL", "REED", "BAILEY", "CHAVEZ", "KELLY", "HOWARD", "RICHARDSON", "WARD", "COX", "RUIZ", "BROOKS", "WATSON", "WOOD", "JAMES", "MENDOZA", "GRAY", "BENNETT", "ALVAREZ", "CASTILLO", "PRICE", "HUGHES", "VASQUEZ", "SANDERS", "JIMENEZ", "LONG", "FOSTER"]  # noqa: E501

# Source: https://github.com/fox-it/cobaltstrike-beacon-data (top spawnto)
PROCESS_NAMES = ["rundll32.exe", "dllhost.exe", "gpupdate.exe", "svchost.exe", "mstsc.exe", "WerFault.exe", "WUAUCLT.exe", "wusa.exe", "runonce.exe", "regsvr32.exe"]  # noqa: E501
# fmt: on

COMPUTERNAME_TEMPLATES = """
WIN-XXXXXXXXXXX
DESKTOP-XXXXXXX
WINDOWS-XXXXXXX
""".split()


def random_computer_name(username: Optional[str] = None) -> str:
    """Returns a random Windows like computer name, if `username` is set it can also return ``<USERNAME>-PC``"""
    if username:
        template = random.choice(COMPUTERNAME_TEMPLATES + [username])
        if template == username:
            username, _, _ = username.partition(".")
            username, _, _ = username.partition(" ")
            return f"{username}-PC".upper()
    else:
        template = random.choice(COMPUTERNAME_TEMPLATES)

    hostname = template.rstrip("X")
    padding_len = len(template) - len(hostname)

    chars = string.ascii_uppercase + string.digits
    padding = "".join(random.choice(chars) for _ in range(padding_len))
    hostname = hostname + padding
    return hostname


def random_username_name() -> str:
    """Returns a random username in the form of ``john.smith`` or ``John Smith``."""
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    if random.getrandbits(1):
        return "{0} {1}".format(first.capitalize(), last.capitalize())
    return f"{first}.{last}".lower()


def random_windows_ver() -> Tuple[int, int, int]:
    """Return a random Windows version in the form of the tuple (major, minor, build)."""

    # Source: https://www.lifewire.com/windows-version-numbers-2625171
    versions = [
        "10.0.22000",  # Windows 11
        "10.0.19041",  # Windows 10
        "6.3.9600",  # Windows 8.1
        "6.2.9200",  # Windows 8
        "6.1.7601",  # Windows 7
        "5.1.2600",  # Windows XP
        "5.0.2195",  # Windows 2000
    ]
    version = random.choice(versions)
    major, minor, build = list(map(int, version.split(".")))
    return (major, minor, build)


def random_process_name() -> str:
    """Return a random process name."""
    return random.choice(PROCESS_NAMES)


def random_internal_ip() -> ipaddress.IPv4Address:
    """Return a random internal RFC1918 IP address."""
    network = random.choice(
        [
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ]
    )
    return ipaddress.IPv4Address(random.randrange(int(network.network_address) + 1, int(network.broadcast_address) - 1))


def log_task(task):
    logger.info("Received Task:")
    task_dt = datetime.datetime.fromtimestamp(task.epoch, tz=datetime.timezone.utc)
    data_r = reprlib.repr(task.data)
    logger.info(f"  - stamp: {task_dt} ({task.epoch:#04x})")
    logger.info(f"  - task: {task.command} ({task.command.value}, {task.command.value:#04x})")
    logger.info(f"  - size: {task.size}")
    logger.info(f"  - data: {data_r}")


# Some helper Callback Response functions
def CallbackError(code: int, n1: int, n2: int, message: str) -> Tuple[int, bytes]:
    return BeaconCallback.CALLBACK_ERROR, p32be(code) + p32be(n1) + p32be(n2) + message.encode() + p32be(0)


def CallbackDebugMessage(message: str) -> Tuple[int, bytes]:
    """This will output ``'[-] DEBUG: <message>'`` to the Team Server console."""
    return CallbackError(code=0, n1=0, n2=0, message=message)


def CallbackOutputMessage(message: str) -> Tuple[int, bytes]:
    """This will output ``'[+] received output: <message>'`` to the Team Server console."""
    return BeaconCallback.CALLBACK_OUTPUT_OEM, message.encode() + p32(0)


class HttpBeaconClient:
    """A Beacon Client that can communicate with a Cobalt Strike Team Server over HTTP."""

    def __init__(self):
        self.task_map = {}
        self.logger = logger

    def run(
        self,
        bconfig: BeaconConfig,
        dry_run=False,
        scheme=None,
        domain=None,
        port=None,
        beacon_id=None,
        pid=None,
        computer=None,
        user=None,
        process=None,
        internal_ip=None,
        arch=None,
        barch=None,
        ansi_cp=58372,
        oem_cp=46337,
        high_integrity=False,
        sleeptime=None,
        jitter=None,
        user_agent=None,
        verbose=None,
        silent=None,
        writer=None,
    ):
        """Run the Beacon Client."""
        self.bconfig = bconfig
        self.counter = int(time.time())

        self.verbose = verbose
        self.dry_run = dry_run
        self.silent = silent

        # Beacon doesn't verify TLS certificates so we disable it here too
        self.verify = False

        # uneven beacon_id's are considered SSH sessions so we ensure that it's even.
        self.beacon_id = beacon_id if beacon_id is not None else (random.getrandbits(32) & 0x7FFFFFFF)
        self.beacon_id = (self.beacon_id - self.beacon_id % 2) & 0xFFFFFFFF
        if self.beacon_id > 0x7FFFFFFF:
            raise ValueError("beacon_id must be less or equal than 2147483647")

        # randomize pid
        self.pid = pid or random.randrange(1000, 5000)

        # The Beacon Session keys (AES and HMAC) are derived from `aes_rand` bytes.
        #   Beacon Session keys are persistent on the Team Server, so to make check-in and responses repeatable for the
        #   same `beacon_id` we use a deterministic `aes_rand`` here so we can re-use the same keys.
        random.seed(self.beacon_id ^ 0xACCE55ED)
        self.aes_rand = random.getrandbits(128).to_bytes(16, "big")

        digest = hashlib.sha256(self.aes_rand).digest()
        self.aes_key = digest[:16]
        self.hmac_key = digest[16:]

        if self.bconfig.protocol not in ("http", "https"):
            raise ValueError("Not a HTTP or HTTPS beacon!")

        if scheme and scheme not in ("http", "https"):
            raise ValueError("Scheme must be either 'http' or 'https'")

        self.user = random_username_name() if user is None else user
        self.computer = random_computer_name(self.user) if computer is None else computer
        self.process = random_process_name() if process is None else process
        info = f"{self.computer}\t{self.user}\t{self.process}"

        # info cannot be larger than 51 bytes, truncate it to be sure.
        info = info[:51]

        # ip is in little endian
        self.internal_ip = ipaddress.IPv4Address(internal_ip or random_internal_ip())
        internal_ip_int = int.from_bytes(self.internal_ip.packed, "little")

        flag = 0
        self.arch = random.choice(["x86", "x64"]) if arch is None else arch
        self.barch = self.arch if barch is None else barch
        self.high_integrity = high_integrity
        if self.barch == "x64":
            flag |= 0x2

        if self.arch == "x64":
            flag |= 0x4

        if self.high_integrity:
            flag |= 0x8

        ver_major, ver_minor, ver_build = random_windows_ver()

        self.metadata = BeaconMetadata(
            magic=0xBEEF,
            ansi_cp=ansi_cp,
            oem_cp=oem_cp,
            bid=self.beacon_id,
            pid=self.pid,
            flag=flag,
            aes_rand=self.aes_rand,
            ip=internal_ip_int,
            ver_major=ver_major,
            ver_minor=ver_minor,
            ver_build=ver_build,
            info=info.encode(),
        )
        self.c2http = C2Http(bconfig, aes_key=self.aes_key, hmac_key=self.hmac_key)

        self.domain = domain or random.choice(self.bconfig.domains)
        self.uri = random.choice(self.bconfig.uris)

        self.scheme = self.bconfig.protocol if scheme is None else scheme
        self.port = port or self.bconfig.port
        self.base_url = f"{self.scheme}://{self.domain}:{self.port}"

        self.get_verb: bytes = self.c2http.get_verb
        self.get_uri: str = random.choice(self.bconfig.uris)
        self.task_url: str = urllib.parse.urljoin(self.base_url, self.get_uri)

        self.submit_verb: bytes = self.c2http.submit_verb
        self.submit_uri: str = self.c2http.submit_uri.decode()
        self.callback_url: str = urllib.parse.urljoin(self.base_url, self.submit_uri)

        self.sleeptime: int = self.bconfig.settings["SETTING_SLEEPTIME"] if sleeptime is None else sleeptime
        self.jitter: int = self.bconfig.settings["SETTING_JITTER"] if jitter is None else jitter
        self.user_agent: str = self.bconfig.settings["SETTING_USERAGENT"] if user_agent is None else user_agent
        self.writer = RecordWriter() if writer is not None else writer

        self.print_settings()
        if dry_run:
            logger.info("Dry run enabled, not continuing.")
            return 0

        if self.writer:
            enable_reprlib_flow_record()
            logger.info("Writing records to %s", writer)

        # start the beacon loop
        logger.info("Starting beacon loop...")
        if self.silent:
            logger.info("Silent mode enabled, empty tasks and check-ins will not be printed.")
        try:
            self._beacon_loop()
        except KeyboardInterrupt:
            return
        finally:
            logger.info("Stopping beacon loop...")
            if self.writer:
                self.writer.close()

    def _initial_get_request(self) -> HttpRequest:
        """Return the initial HttpRequest object for retrieving tasks from the Team Server."""
        return HttpRequest(
            method=self.get_verb,
            uri=self.get_uri.encode(),
            headers={b"User-Agent": self.user_agent.encode()},
            params={},
            body=b"",
        )

    def _initial_post_request(self) -> HttpRequest:
        """Return the initial HttpRequest object for sending callback data to the Team Server."""
        return HttpRequest(
            method=self.submit_verb,
            uri=self.submit_uri.encode(),
            headers={b"User-Agent": self.user_agent.encode()},
            params={},
            body=b"",
        )

    def get_sleep_time(self) -> float:
        """Return the sleep time with jitter for the beacon loop."""
        return self.sleeptime - random.uniform(0, self.sleeptime * self.jitter / 100)

    def register_task(self, command_id: Union[None, int], func):
        """Register a task handler for a given command ID.

        Args:
            command_id: The command ID to register the handler for.
                ``None`` is handler for empty tasks. ``-1`` is a catch-all handler.
            func: The function to call when a task with the given command ID is received.
        """
        if command_id not in self.task_map:
            self.task_map[command_id] = []
        self.task_map[command_id].append(func)

    def get_task(self) -> Optional[TaskPacket]:
        """Get a task from the Team Server."""

        # Encrypt and transform metadata into a HTTP request
        req = self.c2http.transform_get.transform(
            C2Data(metadata=encrypt_metadata(self.metadata, public_key=self.c2http.pub)),
            request=self._initial_get_request(),
        )

        url = urllib.parse.urljoin(self.base_url, req.uri.decode())
        params = {k.decode(): v.decode() for k, v in req.params.items()}
        try:
            response = httpx.request(
                req.method, url, headers=req.headers, params=params, content=req.body, verify=self.verify
            )
            response.raise_for_status()
        except httpx.RequestError as exc:
            self.logger.error("An error occurred while requesting %r : %r", exc.request.url, exc)
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "HttpStatusError, response %s while requesting %r.", exc.response.status_code, exc.request.url
            )
        else:
            req = HttpResponse(
                body=response.content,
                headers=response.headers,
                status=response.status_code,
                reason=response.reason_phrase,
            )
            for packet in self.c2http.iter_recover_http(req):
                if packet.command == BeaconCommand.COMMAND_NOOP:
                    logger.debug("Received NOOP packet: %s", packet)
                    continue
                return packet
        return None

    def send_callback(self, callback_id: int, data: bytes):
        """Send callback data to the Team Server."""
        self.counter += 1

        # Encrypt Callback data and transform into a request
        packet = CallbackPacket(counter=self.counter, size=len(data), callback=callback_id, data=data)
        if self.writer:
            self.writer.write(c2packet_to_record(packet))
            self.writer.flush()

        enc_packet = encrypt_packet(packet.dumps(), **self.c2http.beacon_keys._asdict())

        # Transform data into a HTTP request
        req = self.c2http.transform_submit.transform(
            ClientC2Data(
                id=str(self.beacon_id).encode(),
                output=enc_packet.dumps(),
            ),
            request=self._initial_post_request(),
        )

        # Construct url for callback
        url = urllib.parse.urljoin(self.base_url, req.uri.decode())
        params = {k.decode(): v.decode() for k, v in req.params.items()}
        try:
            response = httpx.request(
                req.method, url, headers=req.headers, params=params, content=req.body, verify=self.verify
            )
            response.raise_for_status()
        except httpx.RequestError as exc:
            self.logger.error("An error occurred while requesting %r : %r", exc.request.url, exc)
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "HttpStatusError, response %s while requesting %r.", exc.response.status_code, exc.request.url
            )

    def handle(self, command: Union[None, int, BeaconCommand]):
        """decorator to register a handler for `command`, if ``None`` it registers a handler for empty tasks"""

        def decorator(func):
            logger.debug("register_task %s -> %s", command, func)
            value = command
            if command and not isinstance(command, int):
                value = command.value
            self.register_task(value, func)
            return func

        return decorator

    def catch_all(self):
        """decorator to handle all `unhandled` commands."""

        def decorator(func):
            self.register_task(-1, func)
            return func

        return decorator

    def print_settings(self):
        if self.dry_run and logger.getEffectiveLevel() >= logging.INFO:
            logger.setLevel(logging.INFO)
            logger.info("Logging level set to INFO for dry run.")
        logger.info("Using %r", self.metadata)
        logger.info("    - barch: %r", self.barch)
        logger.info("    - arch: %r", self.arch)
        logger.info("    - high_integrity: %s", self.high_integrity)
        logger.info("    - internal_ip: %r", str(self.internal_ip))
        logger.info("    - beacon_id: %r", self.beacon_id)
        logger.info("    - information: %r", self.metadata.info)
        logger.info("      + computer: %r", self.computer)
        logger.info("      + user: %r", self.user)
        logger.info("      + process: %r", self.process)
        logger.info("Using %r", self.bconfig)
        logger.info("    - domains: %r -> %r", self.bconfig.domains, self.domain)
        logger.info("    - uris: %r -> %r", self.bconfig.uris, self.uri)
        logger.info("    - port: %u -> %u", self.bconfig.port, self.port)
        logger.info("    - protocol: %r -> %r", self.bconfig.protocol, self.scheme)
        logger.info("    - get_verb: %r", self.get_verb)
        logger.info("    - submit_verb: %r", self.submit_verb)

        logger.info("    - sleeptime (ms): %u -> %u", self.bconfig.sleeptime, self.sleeptime)
        logger.info("    - jitter (%%): %u -> %u", self.bconfig.jitter, self.jitter)

    def get_handlers(self, command_id: Union[int, None]) -> List[Callable]:
        """Get a list of handlers for a given command ID."""
        if command_id is not None:
            task = BeaconCommand(command_id)
            command_name = task.name.replace("COMMAND_", "").lower() if task else "empty_task"
        else:
            command_name = "empty_task"

        on_handler = getattr(self, f"on_{command_name}", None)
        handlers = self.task_map.get(command_id, [])

        # if there is a "on_command" handler, add it to the list
        if on_handler:
            handlers.append(on_handler)

        # if there is no handler, check if there is a catch all handler
        if not handlers:
            handlers = self.task_map.get(-1, [])
            on_catch_all = getattr(self, "on_catch_all", None)
            if on_catch_all:
                handlers.append(on_catch_all)
        return handlers

    def _beacon_loop(self):
        while True:
            task = self.get_task()
            if task:
                log_task(task)
                if self.writer:
                    self.writer.write(c2packet_to_record(task))
            elif not self.silent:
                sleeptime = self.get_sleep_time()
                logger.info("Empty Task, sleeping for %.2f seconds", sleeptime / 1000)
                time.sleep(sleeptime / 1000)
                continue

            command_id = task.command.value if task else None
            handlers = self.get_handlers(command_id)
            for handler in handlers:
                if callable(handler):
                    try:
                        response = handler(task)
                        if response:
                            self.send_callback(*response)
                    except Exception as e:
                        logger.exception(e)

            sleeptime = self.get_sleep_time()
            if not self.silent:
                logger.info("Sleeping for %.2f seconds", sleeptime / 1000)
            time.sleep(sleeptime / 1000)


def build_parser() -> argparse.ArgumentParser:
    """Return the default ArgumentParser for the beacon client."""
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("beacon", metavar="BEACON", help="beacon to use as configuration")

    comms = parser.add_argument_group("beacon communication")
    comms.add_argument(
        "-d",
        "--domain",
        help="override the domain configured in the beacon",
    )
    comms.add_argument(
        "-p",
        "--port",
        type=int,
        help="override the port configured in the beacon",
    )

    timing = parser.add_argument_group("beacon sleep options")
    timing.add_argument(
        "--sleeptime",
        type=int,
        help="override sleeptime settings (in milliseconds)",
    )
    timing.add_argument(
        "--jitter",
        type=int,
        help="override jitter settings (in percentage)",
    )

    metadata = parser.add_argument_group("beacon metadata")
    metadata.add_argument(
        "-c",
        "--computer",
        default=None,
        help="computer name (None = random)",
    )
    metadata.add_argument(
        "-u",
        "--user",
        default=None,
        help="user name (None = random)",
    )
    metadata.add_argument(
        "-P",
        "--process",
        default=None,
        help="process name (None = random)",
    )
    metadata.add_argument(
        "-i",
        "--beacon-id",
        required=False,
        type=int,
        help="beacon id (None = random)",
    )
    metadata.add_argument(
        "-I",
        "--internal-ip",
        help="internal ip (None = random)",
    )

    flags = parser.add_argument_group("beacon metadata flags")
    flags.add_argument(
        "--arch",
        choices=["x86", "x64"],
        default=None,
        help="system architecture (None = random)",
    )
    flags.add_argument(
        "--barch",
        choices=["x86", "x64"],
        default=None,
        help="beacon architecture (None = random)",
    )
    flags.add_argument("--high-integrity", action="store_true", default=False, help="set high integrity flag")

    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        default=False,
        help="show settings and exit",
    )
    writer = parser.add_argument_group("output options")
    writer.add_argument("-w", "--writer", help="record writer")
    writer.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbosity level (-v for INFO, -vv for DEBUG)",
    )
    writer.add_argument(
        "-s",
        "--silent",
        action="store_true",
        default=False,
        help="suppress empty task messages",
    )

    return parser


def parse_commandline_options(parser=None, defaults=None) -> Tuple[argparse.Namespace, Dict[str, Any]]:
    """Helper function to parse commandline options and return a typle of (args, options).

    This method is useful for creating default commandline options for a Beacon client.
    The returned options can be passed to :meth:`HttpBeaconClient.run()` as follows:

    .. code-block:: python

        from dissect.cobaltstrike.client import HttpBeaconClient, parse_commandline_options

        beacon = HttpBeaconClient()

        args, options = parse_commandline_options(defaults={
            "beacon_id": 1234,
            "computer": "dissect",
            "user": "cobaltstrike",
            "process": "calc.exe",
        })

        beacon.run(**options)

    If `parser` is not defined it will use the default argparse parser created by :meth:`build_parser`.
    The `defaults` dictionary can be used to override the default argparse settings.

    Args:
        parser: an instance of :class:`argparse.ArgumentParser`, if `None` it will use the parser created by
            :meth:`client.build_parser`.
        defaults: A dictionary to override the default settings for the argument parser. Unknown keys will be ignored.

    Returns:
        Tuple of (args, options) where `args` is the parsed arguments from the commandline and `options` is a
        dictionary of options that can be passed to :meth:`HttpBeaconClient.run()`.
    """

    parser = parser or build_parser()
    defaults = defaults or {}
    parser.set_defaults(**defaults)
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]

    # Use rich logging if available
    try:
        from rich.logging import RichHandler
        from rich.console import Console

        logging.basicConfig(
            level=level,
            handlers=[RichHandler(console=Console(stderr=True))],
            format="%(message)s",
        )
    except ImportError:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-7s | %(message)s",
        )

    if level == logging.INFO:
        logger.info("INFO logging enabled")
    elif level == logging.DEBUG:
        logger.debug("DEBUG logging enabled")

    # create a dictionary with only arguments that are valid kwargs on .run()
    sig = inspect.signature(HttpBeaconClient.run)
    run_options = {k: v for k, v in vars(args).items() if k in sig.parameters}
    run_options["bconfig"] = BeaconConfig.from_path(args.beacon)
    return args, run_options


@catch_sigpipe
def main():

    parser = build_parser()
    parser.add_argument(
        "--no-warning",
        action="store_true",
        default=False,
        help="disable connect warning",
    )
    args, options = parse_commandline_options(parser)

    if not args.no_warning and not args.dry_run:
        logger.warning(options["bconfig"])
        logger.warning("Connecting to server in 5 seconds... (disable this warning with --no-warning)")
        logger.warning("Press CTRL+C to exit.")
        time.sleep(5)

    client = HttpBeaconClient()
    client.run(**options)


if __name__ == "__main__":
    sys.exit(main())

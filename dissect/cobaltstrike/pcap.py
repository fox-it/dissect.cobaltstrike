import os
import sys
import argparse
import logging

from typing import Optional, Tuple, Iterator

from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.utils import catch_sigpipe, LRUDict, enable_reprlib_cstruct, enable_reprlib_flow_record
from dissect.cobaltstrike import utils
from dissect.cobaltstrike.c2 import C2Http, HttpRequest, HttpResponse, parse_raw_http, C2Packet, enable_reprlib_c2
from dissect.cobaltstrike.c_c2 import BeaconMetadata, BeaconCommand, BeaconCallback

try:
    from flow.record import RecordWriter, RecordDescriptor, extend_record, Record
except ImportError:
    raise ImportError(
        "flow.record is required for writing Beacon records, please install it with `pip install flow.record`"
    )

try:
    from pyshark import FileCapture
    from pyshark.packet.packet import Packet
except ImportError:
    raise ImportError("pyshark is required for PCAP parsing, please install it with `pip install pyshark`")

try:
    from Crypto.PublicKey import RSA
except ImportError:
    raise ImportError(
        "pycryptodome is required for Cobalt Strike C2 traffic parsing, install with `pip install pycryptodome`"
    )

logger = logging.getLogger(__name__)


PacketRecord = RecordDescriptor(
    "pcap/packet/info",
    [
        ("datetime", "packet_ts"),
        ("net.ipaddress", "src_ip"),
        ("uint16", "src_port"),
        ("net.ipaddress", "dst_ip"),
        ("uint16", "dst_port"),
    ],
)
"""Record Descriptor for basic PCAP packet information"""


def packet_to_record(packet: Packet) -> Record:
    """Convert pcap     `packet` to a flow.record."""
    return PacketRecord(
        packet_ts=float(packet.sniff_timestamp),
        src_ip=packet.ip.src,
        src_port=int(packet.tcp.srcport),
        dst_ip=packet.ip.dst,
        dst_port=int(packet.tcp.dstport),
    )


def c2packet_to_record(c2packet: C2Packet) -> Record:
    """Convert `c2packet` to a flow.record."""
    fields = []
    fields.append(("bytes", "raw_http"))
    kv = c2packet._values
    for field in c2packet._type.fields:
        ftype = str(field.type)
        if ftype.startswith("char"):
            ftype = "bytes"
        elif ftype == "uint8":
            ftype = "varint"
        elif ftype in (BeaconCommand.__name__, BeaconCallback.__name__, BeaconMetadata.__name__):
            ftype = "string"
            kv[field.name] = kv[field.name].name
        elif field.name == "epoch":
            ftype = "datetime"
        elif field.name == "ip":
            ftype = "net.ipaddress"
        fields.append((ftype, field.name))
    PacketDescriptor = RecordDescriptor(f"Beacon/{c2packet._type.name}", fields)
    return PacketDescriptor(**kv)


def raw_http_from_packet(packet: Packet) -> bytes:
    """Return the extracted raw HTTP bytes from `packet`."""

    # handle some PyShark quirks
    raw_value = packet.http_raw.value
    if isinstance(raw_value, list):
        raw_value = raw_value.pop(0)

    # handle body data
    raw_http = bytes.fromhex(raw_value)
    if hasattr(packet.http, "file_data_raw"):
        file_data = packet.http.file_data_raw[0]
        raw_http += bytes.fromhex(file_data.raw_value)
    return raw_http


class BeaconCapture:
    """A class representing a beacon capture file.

    Args:
        pcap: A PCAP file containing Cobalt Strike traffic
        nss: Keylog file containg the client random and masterkey in NSS format
        aes_key: AES key used in the beacon session
        hmac_key: hmac key used in the beacon session (optional)
        c2: IP address of the Cobalt Strike C2 server
        config: A Cobalt Strike :class:`BeaconConfig` configuration
        filter: A Wireshark display filter used for filtering the pcap
    """

    def __init__(
        self,
        pcap: str,
        bconfig: Optional[BeaconConfig] = None,
        aes_key: Optional[bytes] = None,
        hmac_key: Optional[bytes] = None,
        rsa_private_key: Optional[RSA.RsaKey] = None,
        verify_hmac: bool = True,
        all_metadata: bool = False,
        extract_beacons: bool = False,
    ) -> None:
        self.pcap = pcap
        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.rsa_private_key = rsa_private_key
        self.bconfig = bconfig
        self.verify_hmac = verify_hmac
        self.all_metadata = all_metadata
        self.packet_number_to_request = LRUDict(maxsize=50)
        self.extract_beacons = extract_beacons

        if self.extract_beacons and self.bconfig:
            raise ValueError("Cannot extract beacons from a pcap when a BeaconConfig is provided")

        self.c2http = None
        if self.bconfig is not None:
            self.c2http = C2Http(
                self.bconfig,
                aes_key=self.aes_key,
                hmac_key=self.hmac_key,
                rsa_private_key=self.rsa_private_key,
                verify_hmac=verify_hmac,
            )

    def __iter__(self) -> Iterator[Tuple[Packet, C2Packet]]:
        """Alias for :meth:`BeaconCapture.iter_parse_pcap`."""
        return self.iter_parse_pcap(self.pcap)

    def iter_parse_pcap(
        self,
        pcap: str,
        all_metadata: Optional[bool] = None,
        nss_keylog_file: Optional[str] = None,
        c2_ip: Optional[str] = None,
        display_filter: str = "http",
        extract_beacons: bool = False,
    ) -> Iterator[Tuple[Packet, C2Packet]]:
        """Yields (packet, c2packet) for every decrypted http C2 packet in the PCAP.

        Args:
            pcap: path to PCAP file
            all_metadata: If ``True`` it will yield all decrypted :class:`BeaconMetadata`. Otherwise, yield only
                the metadata that has not been seen yet. Useful if you want to ignore subsequent check-ins.
            nss_keylog_file: path to a ``SSLKEY_LOG`` file for decrypting TLS traffic in the pcap.
            c2_ip: IP address of the C2, if defined it will be used to filter packets and speed up processing.
            display_filter: A wireshark display filter to apply to the pcap.
                It's recommended to use at least ``http`` (default).

        Yields:
            Tuple of (packet, c2packet)
        """

        all_metadata = self.all_metadata if all_metadata is None else all_metadata

        prefs = {}
        if nss_keylog_file:
            prefs["tls.keylog_file"] = os.path.abspath(nss_keylog_file)

        # Load the pcap file
        capture = FileCapture(
            pcap,
            override_prefs=prefs,
            keep_packets=False,
            display_filter=display_filter,
            include_raw=True,
            use_json=True,
            disable_protocol="urlencoded-form",  # disable this dissector as it triggers json decode errors in pyshark
        )

        metadata_seen = set()
        for packet in capture:
            # Skip non C2 related packets
            if c2_ip and c2_ip not in (packet.ip.src, packet.ip.dst):
                continue

            # Skip non HTTP packets
            if not hasattr(packet, "http"):
                continue

            raw_http = raw_http_from_packet(packet)

            # Parse raw http into a HttpRequest or HttpResponse object, skip packet otherwise
            try:
                http = parse_raw_http(raw_http)
            except ValueError:
                continue

            if isinstance(http, HttpRequest):
                # Keep track of HTTP requests so we can match this against HTTP responses.
                self.packet_number_to_request[packet.number] = http
            elif isinstance(http, HttpResponse) and hasattr(packet.http, "request_in"):
                # If this is a HTTP reponse, try to find the matching HTTP request object
                http_req = self.packet_number_to_request.get(int(packet.http.request_in))
                http = http._replace(request=http_req) if http_req else http

            # We have no beacon config, try to find this in the pcap
            if not self.c2http:
                if isinstance(http, HttpResponse) and http.request:
                    bconfig = self.find_staged_beacon(response=http)
                    if bconfig is not None:
                        self.bconfig = bconfig
                        # Extract and save the beacon config if requested
                        if self.extract_beacons:
                            uri = http.request.uri.decode().replace("/", "").replace(".", "")
                            fname = f"beacon-{uri}.bin"
                            with open(fname, "wb") as f:
                                f.write(http.body)
                                print(
                                    f"[+] Found {bconfig} at {http.request.uri}, extracted beacon payload to {fname!r}"
                                )
                            continue

                        self.c2http = C2Http(
                            self.bconfig,
                            aes_key=self.aes_key,
                            hmac_key=self.hmac_key,
                            rsa_private_key=self.rsa_private_key,
                            verify_hmac=self.verify_hmac,
                        )
                continue

            # HTTP responses to a POST request are not processed by a beacon so we can ignore this response.
            if isinstance(http, HttpResponse) and http.request and http.request.method == self.c2http.submit_verb:
                # if http_req and http_req.method == self.c2http.submit_verb:
                logging.debug("Ignoring HTTP response to beacon POST request (this is normal): %r", http)
                continue

            # Try to recover ClientPacket or ServerPacket from the http object.
            try:
                for c2packet in self.c2http.iter_recover_http(http):
                    if not all_metadata and isinstance(c2packet, BeaconMetadata):
                        if c2packet in metadata_seen:
                            continue
                        metadata_seen.add(c2packet)
                    yield (packet, c2packet)
            except Exception as e:
                logging.debug("[packet %u] Failed to recover http: %r", packet.number, e)

        if not self.bconfig:
            raise ValueError("No beacon config specified and failed to find a beacon config in the PCAP.")

    def find_staged_beacon(self, response: HttpResponse) -> Optional[BeaconConfig]:
        """Returns a `BeaconConfig` if found in the HTTP `response` body. If the response has an associated `request`
        it will check if the request is a stager uri first.

        Args:
            response: The :class:`HttpResponse` object to check for Stager URI and Beacon payload.

        Returns:
            BeaconConfig: The beacon config if found, otherwise `None`.
        """

        if response.request:
            is_stager = False
            uri = response.request.uri.decode("ascii", errors="ignore")
            if utils.is_stager_x86(uri):
                is_stager = True
                logging.info("Found valid x86 checksum8 request: %r", response.request)
            elif utils.is_stager_x64(uri):
                is_stager = True
                logging.info("Found valid x64 checksum8 request: %r", response.request)
            if not is_stager:
                return None

        try:
            config = BeaconConfig.from_bytes(response.body)
            logging.info("Found valid beacon configuration in HTTP response: %r", config)
            logging.info(" + RSA Public Key DER (hex): 0x%s", config.public_key.hex())
            logging.info(" + domain uri pairs: %s", config.domain_uri_pairs)
            logging.info(" + submit uri: %s", config.submit_uri)
            logging.info(" + version: %s", config.version)
            logging.info(" + watermark: 0x%x", config.watermark)
        except ValueError:
            config = None

        return config


@catch_sigpipe
def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("pcap", metavar="PCAP", help="PCAP to parse")
    parser.add_argument("-f", "--filter", help="Wireshark display filter to apply while parsing PCAP")
    parser.add_argument("-c", "--c2", help="Cobalt Strike C2 ip address")
    parser.add_argument("-n", "--nss-keylog-file", help="NSS keylog file to use for decrypting SSL traffic")
    parser.add_argument("-a", "--aes", help="AES key to use (in hex)")
    parser.add_argument("-m", "--hmac", help="HMAC key to use (in hex)")
    parser.add_argument("-k", "--no-hmac-verify", action="store_true", help="Disable HMAC signature verification")
    parser.add_argument("-p", "--private-key", help="Path to RSA private key")
    parser.add_argument("-b", "--beacon", help="Use the BeaconConfig from this Beacon")
    parser.add_argument("-A", "--all-metadata", action="store_true", help="Dump all metadata and not only unique")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument("-e", "--extract-beacons", action="store_true", help="Extract found beacons in pcap")
    parser.add_argument("-w", "--writer", help="Record writer")

    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")

    bconfig = None
    if args.beacon:
        try:
            bconfig = BeaconConfig.from_path(args.beacon)
            logging.info(f"Using beacon configuration from argument: {bconfig}")
        except ValueError:
            logging.error(f"Could not find beacon configuration in: {args.beacon}")
            return 1
    else:
        logging.info("No beacon configuration specified, will try to find one in PCAP...")

    verify_hmac = not args.no_hmac_verify
    aes_key = bytes.fromhex(args.aes) if args.aes else None
    hmac_key = bytes.fromhex(args.hmac) if args.hmac else None

    rsa_private_key = None
    if args.private_key:
        with open(args.private_key, "rb") as key_file:
            rsa_private_key = RSA.import_key(key_file.read())

    beacon_pcap = BeaconCapture(
        pcap=args.pcap,
        bconfig=bconfig,
        aes_key=aes_key,
        hmac_key=hmac_key,
        rsa_private_key=rsa_private_key,
        verify_hmac=verify_hmac,
        all_metadata=args.all_metadata,
        extract_beacons=args.extract_beacons,
    )

    with RecordWriter(args.writer) as writer:
        for (packet, c2packet) in beacon_pcap:
            packet_record = packet_to_record(packet)
            record = c2packet_to_record(c2packet)
            record.raw_http = raw_http_from_packet(packet)
            record = extend_record(packet_record, [record], name=record._desc.name)
            logger.info(c2packet)
            writer.write(record)


if __name__ == "__main__":
    # Ensure we don't spam the console with too much binary data
    enable_reprlib_c2()
    enable_reprlib_flow_record()
    enable_reprlib_cstruct()

    try:
        sys.exit(main())
    except RuntimeError:
        pass

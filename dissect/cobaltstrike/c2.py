"""
This module is responsible for working with Cobalt Strike C2 traffic.
"""
# Python imports
import base64
import random
import logging
import hashlib
import hmac
import io
from urllib.parse import urlparse, parse_qsl

# Typing imports
from typing import List, Optional, Union, Tuple, NamedTuple, Iterator, Dict, overload

# Pycryptodome imports
try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
except ImportError:
    raise ImportError(
        "pycryptodome is required for Cobalt Strike C2 traffic parsing, install with `pip install pycryptodome`"
    )

# flow.record imports
try:
    from flow.record import Record, RecordDescriptor
except ImportError:
    raise ImportError("flow.record is required for logging C2 packet records, install with `pip install flow.record`")

# Local imports
from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.utils import xor, p32be, netbios_encode, netbios_decode, namedtuple_reprlib_repr
from dissect.cobaltstrike.c_c2 import (  # noqa: F401
    c2struct,
    CallbackPacket,
    TaskPacket,
    BeaconMetadata,
    BeaconCommand,
    BeaconCallback,
)

TransformStep = Tuple[str, Union[str, bytes, bool, int]]
"""Type TransformStep."""
C2Packet = Union[BeaconMetadata, TaskPacket, CallbackPacket]
"""Type that is either a :class:`BeaconMetadata`, a :class:`TaskPacket` or a :class:`CallbackPacket`."""

logger = logging.getLogger(__name__)


class EncryptedPacket(NamedTuple):
    """Container to hold ciphertext and HMAC signature."""

    ciphertext: bytes
    signature: bytes

    def dumps(self):
        """Return the EncryptedPacket as a bytes object with a size frame header.

        ``| size | ciphertext | signature |``
        """
        payload = self.ciphertext + self.signature
        return p32be(len(payload)) + payload

    def raise_for_signature(self, hmac_key: bytes):
        """
        Args:
            hmac_key: HMAC key to use for signature verification
        Raises:
            ValueError: if signature of the ciphertext is incorrect.
        """
        signature = hmac.new(hmac_key, self.ciphertext, "sha256").digest()[:16]
        if signature != self.signature:
            raise ValueError(f"Invalid HMAC signature, expected {signature.hex()} got {self.signature.hex()}")


class C2Data(NamedTuple):
    """Container for holding C2 data that is used for transform and recover steps."""

    output: Optional[bytes] = None
    metadata: Optional[bytes] = None
    id: Optional[bytes] = None


class ServerC2Data(C2Data):
    """Container for holding recovered server-side C2Data."""

    def iter_encrypted_packets(self) -> Iterator[EncryptedPacket]:
        """Iterate over ``EncryptedPacket``, parsed from server-side `c2data.output` data.

        For server-side data this is always one packet.
        """
        data = self.output
        if not data:
            return
        fobj = io.BytesIO(data)
        ciphertext = fobj.read(len(data) - 16)
        signature = fobj.read(16)
        yield EncryptedPacket(ciphertext, signature)


class ClientC2Data(C2Data):
    """Container for holding recovered client-side C2Data."""

    def iter_encrypted_packets(self) -> Iterator[EncryptedPacket]:
        """Iterate over ``EncryptedPacket``, parsed from client-side `c2data.output` data.

        For client-side data this could be one or more packets.
        """
        data = self.output
        while data:
            fobj = io.BytesIO(data)
            size = c2struct.uint32(fobj)
            ciphertext = fobj.read(size - 16)
            signature = fobj.read(16)
            data = fobj.read()
            yield EncryptedPacket(ciphertext, signature)


class HttpRequest(NamedTuple):
    """HTTP Request container."""

    method: bytes
    uri: bytes
    params: Dict[bytes, bytes]
    headers: Dict[bytes, bytes]
    body: bytes


class HttpResponse(NamedTuple):
    """HTTP Response container."""

    status: int
    headers: Dict[bytes, bytes]
    reason: bytes
    body: bytes
    request: Optional[HttpRequest] = None


class BeaconKeys(NamedTuple):
    """Helper container to hold beacon session keys (AES + HMAC)."""

    DEFAULT_AES_IV = b"abcdefghijklmnop"

    aes_key: Optional[bytes]
    hmac_key: Optional[bytes] = None
    iv: bytes = DEFAULT_AES_IV

    @classmethod
    def from_aes_rand(cls, aes_rand: bytes, iv: bytes = DEFAULT_AES_IV) -> "BeaconKeys":
        """Create a :class:`BeaconKeys` instance from AES random bytes."""
        aes_key, hmac_key = derive_aes_hmac_keys(aes_rand)
        return cls(aes_key=aes_key, hmac_key=hmac_key, iv=iv)

    @classmethod
    def from_beacon_metadata(cls, metadata: BeaconMetadata, iv: bytes = DEFAULT_AES_IV) -> "BeaconKeys":
        """Create a :class:`BeaconKeys` instance from :class:`BeaconMetadata`."""
        return cls.from_aes_rand(metadata.aes_rand, iv=iv)


def enable_reprlib_c2():
    """Enables reprlib __repr__ for most of the namedtuple classes in this module."""
    HttpRequest.__repr__ = namedtuple_reprlib_repr
    HttpResponse.__repr__ = namedtuple_reprlib_repr
    C2Data.__repr__ = namedtuple_reprlib_repr


def c2packet_to_record(c2packet: C2Packet) -> Record:
    """Convert `c2packet` to a flow.record."""
    fields = [("bytes", "raw_http")]
    kv = dict(c2packet._values)
    for field in c2packet._type.fields:
        ftype = str(field.type)
        if ftype.startswith("char"):
            ftype = "bytes"
        elif ftype == "uint8":
            ftype = "varint"
        elif ftype in ("BeaconCommand", "BeaconCallback", "BeaconMetadata"):
            ftype = "string"
            kv[field.name] = kv[field.name].name
        elif field.name == "epoch":
            ftype = "datetime"
        elif field.name == "ip":
            ftype = "net.ipaddress"
        fields.append((ftype, field.name))
    PacketDescriptor = RecordDescriptor(f"Beacon/{c2packet._type.name}", fields)
    return PacketDescriptor(**kv)


def parse_raw_http(data: bytes) -> Union[HttpRequest, HttpResponse]:
    """Parse a raw HTTP request/response bytes and returns a :class:`HttpRequest` or :class:`HttpResponse` accordingly.

    Args:
        data: raw HTTP request or response data bytes.

    Returns:
        Either a :class:`HttpRequest` or :class:`HttpResponse` object based on the data.

    Raises:
        ValueError: if it cannot be parsed as :class:`HttpRequest` or :class:`HttpResponse`.
    """

    header_data, _, body = data.partition(b"\r\n\r\n")
    first_line, _, header_data = header_data.partition(b"\r\n")

    headers = {}
    for header in header_data.split(b"\r\n"):
        key, _, value = header.partition(b": ")
        headers[key] = value

    # HTTP/1.1 200 OK
    if first_line.upper().startswith(b"HTTP/"):
        parts = first_line.rstrip().split()
        if len(parts) != 3:
            raise ValueError(f"Error in parsing response status line: {first_line!r}")
        _version, status, reason = parts
        status_code = int(status.decode())
        return HttpResponse(body=body, headers=headers, status=status_code, reason=reason)

    # GET /uri HTTP/1.1
    parts = first_line.rstrip().split()
    if len(parts) != 3:
        raise ValueError(f"Error in parsing request status line: {first_line!r}")
    method, uri, _version = parts

    # sanitize uri bytes for `urlparse()` to avoid possible decode errors
    uri = uri.decode("ascii", errors="ignore").encode()
    result = urlparse(uri)
    uri = result.path
    params = dict(parse_qsl(result.query))
    return HttpRequest(method=method, body=body, headers=headers, uri=uri, params=params)


class HttpDataTransform:
    """Transform and recover Cobalt Strike HTTP C2 data using transformation steps."""

    def __init__(self, steps: List[TransformStep], reverse: bool = False, build: str = None) -> None:
        self.tsteps: List[TransformStep] = steps
        self.rsteps: List[TransformStep] = steps[::-1]

        if reverse:
            self.tsteps, self.rsteps = self.rsteps, self.tsteps

        if build is not None:
            build_step = ("BUILD", build)
            self.tsteps.insert(0, build_step)
            self.rsteps.append(build_step)

    def transform(self, c2data: C2Data, request: Optional[HttpRequest] = None) -> HttpRequest:
        """Transform `c2data` information into a :class:`HttpRequest` namedtuple.

        Args:
            c2data: :class:`C2Data` named tuple that needs to be transformed
            request: Optional initial HTTP request data

        Returns:
            HttpRequest: Transformed HTTP request data
        """
        # logger.debug("transform steps: %r", self.tsteps)
        request = request or HttpRequest(method=b"", uri=b"", body=b"", params={}, headers={})
        uri = request.uri
        params = request.params
        headers = request.headers
        body = request.body
        data: bytes = b""
        for (step, step_val) in self.tsteps:
            # logger.debug("transform step %r, %r", step, step_val)
            step = step.lower()
            if step == "append":
                if isinstance(step_val, int):
                    step_val = b"X" * step_val
                assert isinstance(step_val, bytes)
                data = data + step_val
            elif step == "prepend":
                if isinstance(step_val, int):
                    step_val = b"X" * step_val
                assert isinstance(step_val, bytes)
                data = step_val + data
            elif step == "base64":
                data = base64.b64encode(data)
            elif step == "base64url":
                data = base64.urlsafe_b64encode(data)
            elif step == "netbios":
                data = netbios_encode(data).lower()
            elif step == "netbiosu":
                data = netbios_encode(data).upper()
            elif step == "mask":
                mask = p32be(random.getrandbits(32))
                data = mask + xor(data, mask)
            elif step == "print":
                body = data
            elif step == "header":
                assert isinstance(step_val, bytes)
                headers[step_val] = data
            elif step == "_header" or step == "_hostheader":
                assert isinstance(step_val, bytes)
                key, _, val = step_val.partition(b": ")
                headers[key] = val
            elif step == "uri_append":
                uri += data
            elif step == "parameter":
                assert isinstance(step_val, bytes)
                params[step_val] = data
            elif step == "build":
                if step_val == "output":
                    data = c2data.output or b""
                elif step_val == "id":
                    data = c2data.id or b""
                elif step_val == "metadata":
                    data = c2data.metadata or b""
            else:
                raise ValueError("Unknown transform step with value: {}".format((step, step_val)))
        return request._replace(body=body, params=params, uri=uri, headers=headers)

    @overload
    def recover(self, http: HttpRequest) -> ClientC2Data:
        ...

    @overload
    def recover(self, http: HttpResponse) -> ServerC2Data:
        ...

    def recover(self, http: Union[HttpRequest, HttpResponse]) -> Union[ClientC2Data, ServerC2Data]:
        """Recovers the transformed data in `http` object and returns a C2Data namedtuple.

        Args:
            http: a :class:`HttpRequest` or :class:`HttpResponse` namedtuple
        Returns:
            Either a :class:`ClientC2Data` or :class:`ServerC2Data` namedtuple based on the `http` data.
        """
        assert isinstance(http, (HttpRequest, HttpResponse)), "argument should be a HttpRequest or HttpResponse"
        build_metadata = None
        build_output = None
        build_id = None
        data = b""
        # logger.debug("recover steps: %r", self.rsteps)
        for (step, step_val) in self.rsteps:
            step = step.lower()
            if step == "append":
                if isinstance(step_val, bytes):
                    step_val = len(step_val)
                assert isinstance(step_val, int)
                data = data[:-step_val]
            elif step == "prepend":
                if isinstance(step_val, bytes):
                    step_val = len(step_val)
                assert isinstance(step_val, int)
                data = data[step_val:]
            elif step == "base64":
                data = base64.b64decode(data + b"==")
            elif step == "base64url":
                data = base64.urlsafe_b64decode(data + b"==")
            elif step == "netbios":
                data = netbios_decode(data.upper())
            elif step == "netbiosu":
                data = netbios_decode(data)
            elif step == "mask":
                data = xor(data[4:], data[:4])
            elif step == "print":
                data = http.body
            elif step == "uri_append":
                assert isinstance(http, HttpRequest)
                data = http.uri
            elif step == "header":
                assert isinstance(step_val, bytes)
                data = http.headers[step_val]
            elif step == "parameter":
                assert isinstance(http, HttpRequest)
                assert isinstance(step_val, bytes)
                data = http.params[step_val]
            elif step == "build":
                if step_val == "output":
                    build_output = data
                elif step_val == "id":
                    build_id = data
                elif step_val == "metadata":
                    build_metadata = data
            elif step in ("_header", "_hostheader"):
                pass
            else:
                raise ValueError("Unknown recover step with value: {}".format((step, step_val)))

        if isinstance(http, HttpRequest):
            return ClientC2Data(output=build_output, id=build_id, metadata=build_metadata)
        return ServerC2Data(output=build_output, id=build_id, metadata=build_metadata)


class C2Http:
    """Class for decrypting and encrypting Cobalt Strike HTTP C2 traffic.

    It requires to be initialized with a :class:`BeaconConfig` and one of the following *key* material:

        * `aes_key` and optionally `hmac_key`
        * `aes_rand`
        * `rsa_private_key` (most preferred when available)
    """

    def __init__(
        self,
        bconfig: BeaconConfig,
        aes_key: Optional[bytes] = None,
        hmac_key: Optional[bytes] = None,
        aes_rand: Optional[bytes] = None,
        rsa_private_key: Optional[RSA.RsaKey] = None,
        verify_hmac=True,
    ) -> None:
        self.bconfig = bconfig

        if aes_rand and aes_key:
            raise ValueError("Cannot specify both aes_rand and aes_key.")
        if not any([aes_key, aes_rand, rsa_private_key]):
            raise ValueError("One of the following arguments is required: aes_key, aes_rand, rsa_private_key")

        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.verify_hmac = verify_hmac

        if aes_rand:
            self.aes_key, self.hmac_key = derive_aes_hmac_keys(aes_rand)

        if self.aes_key is not None and len(self.aes_key) != 16:
            raise ValueError(f"AES key must be 16 bytes, got: {self.aes_key!r}")

        if self.hmac_key is not None and len(self.hmac_key) != 16:
            raise ValueError(f"HMAC key must be 16 bytes, got: {self.hmac_key!r}")

        self.pub = RSA.import_key(bconfig.public_key)
        self.priv = rsa_private_key
        if self.priv:
            logger.debug("RSA Private Key: %r", self.priv)
            logger.debug("RSA Public Key: %r", self.pub)
            assert self.priv.n == self.pub.n, ValueError(
                f"RSA PrivateKey does not match PublicKey pair, {self.priv.n:#x} != {self.pub.n:#x}"
            )

        if self.bconfig.is_trial:
            raise ValueError("Trial beacons are not yet supported, please submit an issue")

        # Get the different URIs used by the beacon for matching HTTP requests (note everything is in bytes)
        self.submit_uri: bytes = bconfig.settings["SETTING_SUBMITURI"].encode()
        self.submit_verb: bytes = bconfig.settings["SETTING_C2_VERB_POST"].encode()
        self.get_uris: Tuple[bytes, ...] = tuple(uri.encode() for uri in bconfig.uris)
        self.get_verb: bytes = bconfig.settings["SETTING_C2_VERB_GET"].encode()

        # Load transform/recover steps from beacon config
        self.transform_submit = HttpDataTransform(steps=bconfig.settings["SETTING_C2_POSTREQ"])
        self.transform_get = HttpDataTransform(steps=bconfig.settings["SETTING_C2_REQUEST"])
        self.transform_response = HttpDataTransform(
            steps=bconfig.settings["SETTING_C2_RECOVER"], reverse=True, build="output"
        )

        # Used to map unencrypted metadata to decrypted BeaconMetadata
        self.metadata_cache: Dict[bytes, BeaconMetadata] = {}

        # Default decryption keys
        self.beacon_keys = BeaconKeys(aes_key=self.aes_key, hmac_key=self.hmac_key)

    def get_transform_for_http(self, http: Union[HttpRequest, HttpResponse, bytes]) -> HttpDataTransform:
        """Return the correct :class:`HttpDataTransform` instance for given `http`.

        Args:
            http: either a :class:`HttpRequest` or :class:`HttpResponse` object or raw HTTP bytes.

        Returns:
            HttpDataTransform: The correct :class:`HttpDataTransform` instance for given `http`.

        Raises:
            ValueError: if no correct transform can be found for given `http` object.
        """
        http = parse_raw_http(http) if isinstance(http, bytes) else http

        if isinstance(http, HttpRequest):
            if http.method == self.get_verb and http.uri.startswith(self.get_uris):
                return self.transform_get
            elif http.method == self.submit_verb and http.uri.startswith(self.submit_uri):
                return self.transform_submit
        elif isinstance(http, HttpResponse):
            return self.transform_response
        raise ValueError(f"Possible unrelated HTTP Request or Response, cannot find correct transform for {http!r}")

    def iter_recover_http(
        self, http: Union[bytes, HttpRequest, HttpResponse], keys: Optional[BeaconKeys] = None
    ) -> Iterator[C2Packet]:
        """Yield decrypted :class:`C2Packet` objects from given `http` object.

        You can pass your own set of :class:`BeaconKeys` `keys` to use for decryption instead of the default
        initialized ones. This can be useful if you are processing multiple Beacon sessions and do some sort of session
        tracking outside this class.

        Args:
            http: A :class:`HttpRequest` or :class:`HttpResponse` object, or raw HTTP request or response bytes.
            keys: Optional :class:`BeaconKeys` to use for decryption instead of current default keys.

        Yields:
            C2Packet: A :class:`C2Packet` object for each decrypted packet found in the HTTP request or response.
        """
        http = parse_raw_http(http) if isinstance(http, bytes) else http
        keys = keys or self.beacon_keys

        transform = self.get_transform_for_http(http)
        c2data = transform.recover(http)

        # decrypt c2data.metadata, if available and we have a private key
        if c2data.metadata and self.priv:
            metadata = self.metadata_cache.get(c2data.metadata)
            if metadata is None:
                metadata = decrypt_metadata(c2data.metadata, self.priv)
                self.metadata_cache[c2data.metadata] = metadata
                # if we do not have an AES key or HMAC key yet, we derive it.
                if not all([self.beacon_keys.aes_key, self.beacon_keys.hmac_key]):
                    aes_key, hmac_key = derive_aes_hmac_keys(metadata.aes_rand)
                    self.beacon_keys = BeaconKeys(aes_key, hmac_key)
                    logging.info("Derived AES + HMAC keys from %r", metadata)
            yield metadata

        # decrypt c2data.output, if any
        for enc_packet in c2data.iter_encrypted_packets():
            plaintext = decrypt_packet(enc_packet, verify=self.verify_hmac, **keys._asdict())
            if isinstance(c2data, ClientC2Data):
                yield CallbackPacket(plaintext)
            elif isinstance(c2data, ServerC2Data):
                yield TaskPacket(plaintext)


# ------------------
# Crypto functions
# ------------------


def decrypt_metadata(encrypted_metadata: bytes, private_key: RSA.RsaKey) -> BeaconMetadata:
    """Decrypt `encrypted_metadata` using RSA `private_key`.

    Args:
        encrypted_metadata: the encrypted metadata bytes
        private_key: the RSA private key used for decryption

    Returns:
        BeaconMetadata: The decrypted metadata.

    Raises:
        ValueError: if RSA failed to decrypt or metadata magic is invalid
    """
    cipher = PKCS1_v1_5.new(private_key)
    pt = cipher.decrypt(encrypted_metadata, None)
    if pt is None:
        raise ValueError("Failed to RSA decrypt metadata")
    metadata = BeaconMetadata(pt)
    if metadata.magic != 0xBEEF:
        raise ValueError(f"Invalid metadata magic, got {metadata.magic:08x}, expected 0xbeef")
    return metadata


def encrypt_metadata(metadata: BeaconMetadata, public_key: RSA.RsaKey) -> bytes:
    """Encrypt `metadata` using RSA `public_key`.

    Args:
        metadata: :class:`BeaconMetadata` object to encrypt
        public_key: the RSA public key used for encryption

    Returns:
        The encrypted metadata as bytes
    """
    cipher = PKCS1_v1_5.new(public_key)
    metadata.size = len(metadata) - 8
    return cipher.encrypt(metadata.dumps())


def derive_aes_hmac_keys(aes_random: bytes) -> Tuple[bytes, bytes]:
    """Derive the AES and HMAC keys from the `aes_random` bytes.

    Args:
        aes_random: the bytes to derive the keys from

    Returns:
        Tuple of (aes_key, hmac_key)
    """
    digest = hashlib.sha256(aes_random).digest()
    return digest[:16], digest[16:]


def pad(data: bytes, block_size: int = AES.block_size) -> bytes:
    """Mimics the padding behaviour in Cobalt Strike (which is to fill it with b'A').

    Args:
        data: the data to pad
        block_size: the block size to use for padding

    Returns:
        The padded data
    """
    to_pad = block_size - len(data) % block_size
    return data + b"A" * to_pad


def encrypt_data(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """AES encrypt `data` with given `aes_key` and `iv`.

    Args:
        data: the data to encrypt
        aes_key: the AES key to use
        iv: the initialization vector to use

    Returns:
        The encrypted data as bytes
    """
    if aes_key is None:
        raise ValueError("Cannot encrypt without AES key")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(data))


def decrypt_data(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """AES decrypt the `data` with given `aes_key` and `iv` and return the decrypted bytes.

    Args:
        data: the encrypted data
        aes_key: the AES key to use for decryption
        iv: the AES IV to use for decryption

    Returns:
        The decrypted data as bytes
    """
    if aes_key is None:
        raise ValueError("Cannot decrypt without AES key")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    # Beacon and Team Server does not unpad data
    return cipher.decrypt(data)


def decrypt_packet(
    packet: EncryptedPacket,
    aes_key: bytes,
    hmac_key: Optional[bytes] = None,
    iv: bytes = BeaconKeys.DEFAULT_AES_IV,
    verify: bool = True,
) -> bytes:
    """Decrypt :class:`EncryptedPacket` `packet` and return the decrypted plaintext bytes.

    If `hmac_key`  is defined, the signature of the ciphertext is verified first before decrypting.

    Args:
        packet: the :class:`EncryptedPacket` to decrypt
        aes_key: the AES key to use for decryption
        hmac_key: the HMAC key to use for signature verification
        iv: the AES IV to use for decryption
        verify: whether to verify the HMAC signature of the ciphertext

    Returns:
        The decrypted plaintext bytes
    """
    if verify:
        if not hmac_key:
            raise ValueError("Cannot verify signature without hmac_key.")
        packet.raise_for_signature(hmac_key)
    return decrypt_data(packet.ciphertext, aes_key, iv)


def encrypt_packet(
    plaintext: bytes, aes_key: bytes, hmac_key: bytes, iv: bytes = BeaconKeys.DEFAULT_AES_IV
) -> EncryptedPacket:
    """Encrypt `plaintext` bytes and return a :class:`EncryptedPacket`.

    Args:
        plaintext: the plaintext bytes to encrypt
        aes_key: the AES key to use for encryption
        hmac_key: the HMAC key to use for signature generation
        iv: the AES IV to use for encryption
    Returns:
        The :class:`EncryptedPacket` containing the ciphertext and HMAC signature
    """
    ciphertext = encrypt_data(plaintext, aes_key=aes_key, iv=iv)
    signature = hmac.new(hmac_key, ciphertext, "sha256").digest()[:16]
    return EncryptedPacket(ciphertext, signature)

import hmac
import random
import pytest

from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.c2 import (
    C2Http,
    HttpRequest,
    HttpResponse,
    BeaconMetadata,
    TaskPacket,
    BeaconCommand,
    BeaconCallback,
    ClientC2Data,
    ServerC2Data,
    EncryptedPacket,
    HttpDataTransform,
    BeaconKeys,
    parse_raw_http,
)
from dissect.cobaltstrike.c2 import encrypt_metadata, encrypt_data, encrypt_packet
from dissect.cobaltstrike.c2 import decrypt_metadata, decrypt_packet
from dissect.cobaltstrike.c2 import derive_aes_hmac_keys, pad

from Crypto.PublicKey import RSA

# Test data sources:
#  - https://www.malware-traffic-analysis.net/2021/02/02/index.html
#  - https://blog.nviso.eu/2021/10/27/cobalt-strike-using-known-private-keys-to-decrypt-traffic-part-2/

http_request_checkin = (
    b"GET /ptj HTTP/1.1\r\n"
    b"Accept: */*\r\n"
    b"Cookie: KN9zfIq31DBBdLtF4JUjmrhm0lRKkC/I/zAiJ+Xxjz787h9yh35cRjEnXJAwQcWP4chXobXT/E5YrZjgreeGTrORnj//A5iZw2TClEnt++gLMyMHwgjsnvg9czGx6Ekpz0L1uEfkVoo4MpQ0/kJk9myZagRrPrFWdE9U7BwCzlE=\r\n"  # noqa: E501
    b"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)\r\n"
    b"Host: redacted:8080\r\n"
    b"Connection: Keep-Alive\r\n"
    b"Cache-Control: no-cache\r\n\r\n"
)
http_response_task_file_list = (
    b"HTTP/1.1 200 OK\r\n"
    b"Date: Tue, 2 Feb 2021 16:32:16 GMT\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Length: 48\r\n\r\n"
    b"\xea\xa7eW\x17\xb9\x84[\x8fE\x8cS\x13p\xf8\x83\x9e\xba\xb6\x15\x9d\xcc\xd0c\x06\x91s9\xca7\x90U\xdc1V\xd9|z\x14[\xa4\xe2Q\xd0s\x8d\x8f@"  # noqa: E501
)
http_post_callback = (
    b"POST /submit.php?id=242569267 HTTP/1.1\r\n"
    b"Accept: */*\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)\r\n"
    b"Host: redacted:8080\r\n"
    b"Content-Length: 148\r\n"
    b"Connection: Keep-Alive\r\n"
    b"Cache-Control: no-cache\r\n\r\n"
    b"\x00\x00\x00\x90U@D\x97\x8d\xf1L\xda\xd3\r\x98\xed\x10\xe0\xff#\x97W\xde\x17\xa1:x\xeb\xa3\xe4\x89 \xaeq\xde\xae\xfc\xd87\x1d\x9f\xed\x95K\x19\x94n\xf2\xeb\x1eO\x9e\xad\xd4`-\x7f\x82m\\\xe2\x06<\xda\xefjx@\x04;\xac\xdd\x13P\x9d\xaf\x86\xc6\xd4*,9\xe7\xe2\xfa\xe2\xc3\xdc}92\x94A\x90\xbb\x01\xa3' \\PB\x86q\xf6y\xda:\xf7\xbe'\xba\xaa\xbe_\xd8\"\x96h\x11\xe4)!\x9d\x8d\xfe\xc2\x83\xbe\xee!\xa0:5\xa6\x00>[\x05\xdf\x12F\xaaN\xcc\xf1\x10\x97"  # noqa: E501
)

rsa_private = RSA.construct(
    (
        117427205845348485244015322822129549811247730233368658993207011448441178690532504818038502351592533412903992324819587429509365062557617469076848055744603713033993541074262699306731808123110723658011905734336339013104629861585165807593797388931565187434008170828073710103901578805379036254367111549325081196051,  # noqa: E501
        65537,
        63143753317910889550701801906932991514689126160094983163397901802867320417978485470688235063742198605431276889680136115527710059502159043406582576750470401211113680307065390018237044267922185483204732358859031408916065489305405381946331418517893749803908480784415439301698216721664479409505596732533109402129,  # noqa: E501
    )
)


@pytest.fixture
def bconfig(c2test_beacon_path) -> BeaconConfig:
    return BeaconConfig.from_path(c2test_beacon_path)


@pytest.fixture
def c2http(c2test_beacon_bconfig) -> C2Http:
    aes_rand = bytes.fromhex("caeab4f452fe41182d504aa24966fbd0")
    aes_key, hmac_key = derive_aes_hmac_keys(aes_rand)
    return C2Http(c2test_beacon_bconfig, aes_key=aes_key, hmac_key=hmac_key, rsa_private_key=rsa_private)


def test_parse_raw_http_request():
    http = parse_raw_http(http_request_checkin)
    assert isinstance(http, HttpRequest)
    assert http.body == b""
    assert http.uri == b"/ptj"
    assert http.method == b"GET"
    assert set(http.headers.keys()) == set(
        [b"Accept", b"Cookie", b"User-Agent", b"Host", b"Connection", b"Cache-Control"]
    )
    assert http.headers[b"User-Agent"] == b"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)"


def test_parse_raw_http_response():
    http = parse_raw_http(http_response_task_file_list)
    assert isinstance(http, HttpResponse)
    assert http.status == 200
    assert http.reason == b"OK"
    assert http.headers[b"Content-Length"] == b"48"
    assert len(http.body) == 48


def test_parse_raw_http_invalid():
    http = b"INVALIDHTTPREQUEST"
    with pytest.raises(ValueError):
        parse_raw_http(http)

    http = b"\x01" * 1024
    with pytest.raises(ValueError):
        parse_raw_http(http)

    http = b"\r\n" * 100
    with pytest.raises(ValueError):
        parse_raw_http(http)


def test_http_request_equals():
    http1 = parse_raw_http(http_request_checkin)
    http2 = parse_raw_http(http_request_checkin)
    assert http1 == http2


def test_transform_decrypt_metadata():
    http = parse_raw_http(http_request_checkin)
    get_transform = HttpDataTransform(
        steps=[("HEADER", b"Cookie"), ("BASE64", True), ("BUILD", "metadata")], reverse=True
    )

    c2data = get_transform.recover(http)
    assert c2data
    assert c2data.metadata
    assert c2data.id is None
    assert c2data.output is None
    assert isinstance(c2data.metadata, bytes)

    metadata = decrypt_metadata(c2data.metadata, rsa_private)
    assert metadata
    assert metadata.magic == 0xBEEF
    assert metadata.ip == 0x6F09060A
    assert metadata.ver_major == 10
    assert metadata.ver_minor == 0
    assert metadata.ver_build == 19042
    assert metadata.flag == 0x4
    assert metadata.pid == 7292
    assert metadata.bid == 105175268
    assert metadata.ansi_cp == 0xE404
    assert metadata.oem_cp == 0xB501
    assert metadata.info == b"DESKTOP-Q21RU7A\tmaxwell.carter\tsvchost.exe"
    assert metadata.aes_rand.hex() == "caeab4f452fe41182d504aa24966fbd0"


def test_encrypt_decrypt_metadata():
    priv = RSA.generate(bits=1024)

    aes_rand = random.getrandbits(128).to_bytes(16, "big")
    metadata = BeaconMetadata(
        magic=0xBEEF,
        pid=0x1337,
        aes_rand=aes_rand,
        bid=0x10F2C,
        info=b"HELLO\tWORLD\t!!!",
    )
    blob = encrypt_metadata(metadata, priv.public_key())
    d_metadata = decrypt_metadata(blob, priv)

    assert d_metadata.dumps() == metadata.dumps()
    assert d_metadata.magic == 0xBEEF
    assert d_metadata.pid == 0x1337
    assert d_metadata.bid == 0x10F2C
    assert d_metadata.aes_rand == aes_rand


def test_transform_decrypt_task():
    http = parse_raw_http(http_response_task_file_list)
    assert isinstance(http, HttpResponse)

    # Transform data
    response_transform = HttpDataTransform(steps=[("print", True), ("BUILD", "output")], reverse=True)
    c2data = response_transform.recover(http)
    assert isinstance(c2data, ServerC2Data)
    assert isinstance(c2data.output, bytes)

    # Iteratate over EncryptedPacket
    enc_packets = []
    for packet in c2data.iter_encrypted_packets():
        assert isinstance(packet, EncryptedPacket)
        enc_packets.append(packet)
    assert len(enc_packets) == 1
    enc_packet = enc_packets.pop()

    # Decrypt packet
    keys = BeaconKeys.from_aes_rand(bytes.fromhex("caeab4f452fe41182d504aa24966fbd0"))
    plaintext = decrypt_packet(enc_packet, **keys._asdict())
    assert (
        plaintext == b"`\x19~\x90\x00\x00\x00\x13\x00\x00\x005\x00\x00\x00\x0b\x00\x00\x00\xba\x00\x00\x00\x03.\\*AAAAA"
    )

    # TaskPacket
    task = TaskPacket(plaintext)
    assert task.epoch == 0x60197E90
    assert task.total_size == 19
    assert task.command == BeaconCommand.COMMAND_FILE_LIST
    assert task.size == 11
    assert task.data == b"\x00\x00\x00\xba\x00\x00\x00\x03.\\*"
    assert len(task.data) == task.size


def test_c2data_empty_iter_encrypted_packets():
    c2data = ServerC2Data()
    assert list(c2data.iter_encrypted_packets()) == []

    c2data = ClientC2Data()
    assert list(c2data.iter_encrypted_packets()) == []


def test_c2data_from_http_request_checkin(c2http):
    http = parse_raw_http(http_request_checkin)
    transform = c2http.get_transform_for_http(http)
    c2data = transform.recover(http)

    assert c2data.output is None
    assert c2data.id is None
    assert c2data.metadata

    metadata = decrypt_metadata(c2data.metadata, rsa_private)
    assert isinstance(metadata, BeaconMetadata)


def test_c2data_from_http_post_callback(c2http: C2Http):
    http = parse_raw_http(http_post_callback)
    transform = c2http.get_transform_for_http(http)
    c2data = transform.recover(http)

    assert c2data.output == http.body
    assert c2data.metadata is None
    assert c2data.id == b"242569267"

    for enc_packet in c2data.iter_encrypted_packets():
        enc_packet.raise_for_signature(c2http.hmac_key)


def test_c2data_from_http_response(c2http):
    http = parse_raw_http(http_response_task_file_list)
    transform = c2http.get_transform_for_http(http)
    c2data = transform.recover(http)

    assert c2data.output == http.body
    assert c2data.metadata is None
    assert c2data.id is None


def test_c2http_recover_with_aes_key_and_no_hmac(bconfig):
    aes_rand = bytes.fromhex("caeab4f452fe41182d504aa24966fbd0")
    aes_key, _ = derive_aes_hmac_keys(aes_rand)
    c2http = C2Http(bconfig, aes_key=aes_key, hmac_key=None)

    with pytest.raises(ValueError, match="Cannot verify signature without hmac_key."):
        list(c2http.iter_recover_http(http_response_task_file_list))


def test_c2http_recover_with_aes_key_and_no_hmac_no_verify(bconfig):
    aes_rand = bytes.fromhex("caeab4f452fe41182d504aa24966fbd0")
    aes_key, _ = derive_aes_hmac_keys(aes_rand)
    c2http = C2Http(bconfig, aes_key=aes_key, hmac_key=None, verify_hmac=False)

    for packet in c2http.iter_recover_http(http_response_task_file_list):
        assert packet.command == BeaconCommand.COMMAND_FILE_LIST


def test_c2http_init_with_no_keys(bconfig):
    with pytest.raises(ValueError, match="One of the following arguments is required: .*"):
        C2Http(bconfig)


def test_c2http_init_with_aes_rand_and_aes_key(bconfig):
    with pytest.raises(ValueError, match="Cannot specify both .*"):
        C2Http(bconfig, aes_key=b"A" * 16, aes_rand=b"B" * 16)


def test_c2http_recover_with_aes_key_and_hmac(bconfig):
    aes_rand = bytes.fromhex("caeab4f452fe41182d504aa24966fbd0")
    aes_key, hmac_key = derive_aes_hmac_keys(aes_rand)
    c2http = C2Http(bconfig, aes_key=aes_key, hmac_key=hmac_key)

    client_packets = list(c2http.iter_recover_http(http_request_checkin))
    server_packets = list(c2http.iter_recover_http(http_response_task_file_list))

    assert len(client_packets) == 0
    assert len(server_packets) == 1

    assert server_packets[0].command == BeaconCommand.COMMAND_FILE_LIST


def test_c2http_recover_with_aes_rand_only(bconfig):
    aes_rand = bytes.fromhex("caeab4f452fe41182d504aa24966fbd0")
    c2http = C2Http(bconfig, aes_rand=aes_rand, rsa_private_key=rsa_private)

    client_packets = list(c2http.iter_recover_http(http_request_checkin))
    server_packets = list(c2http.iter_recover_http(http_response_task_file_list))

    assert len(client_packets) == 1
    assert len(server_packets) == 1

    assert isinstance(client_packets[0], BeaconMetadata)
    assert client_packets[0].bid == 105175268
    assert server_packets[0].command == BeaconCommand.COMMAND_FILE_LIST


def test_c2http_recover_with_rsa_private_only(bconfig):
    # We test with only RSA private key and check if we can decrypt subsequent packets.
    c2http = C2Http(bconfig, rsa_private_key=rsa_private)
    for c2packet in c2http.iter_recover_http(http_request_checkin):
        assert isinstance(c2packet, BeaconMetadata)
    for c2packet in c2http.iter_recover_http(http_response_task_file_list):
        assert isinstance(c2packet, TaskPacket)


def test_c2http_conflicts(bconfig):
    with pytest.raises(ValueError, match="One of the following arguments is required: .*"):
        C2Http(bconfig)

    with pytest.raises(ValueError, match="Cannot specify both aes_rand and aes_key."):
        C2Http(bconfig, aes_key=b"A" * 16, aes_rand=b"test")


def test_c2http_multiple_callbacks(bconfig):
    aes_rand = bytes.fromhex("caeab4f452fe41182d504aa24966fbd0")
    c2http = C2Http(bconfig, aes_rand=aes_rand, rsa_private_key=rsa_private)
    raw_http = (
        b"POST /submit.php?id=242569267 HTTP/1.1\r\n"
        b"Accept: */*\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; WOW64; Trident/5.0)\r\n"
        b"Content-Length: 104\r\n"
        b"Connection: Keep-Alive\r\n"
        b"Cache-Control: no-cache\r\n\r\n"
        b"\x00\x00\x000m{L\xb8cZt\x84\xa8\x15]\xaedkuJ\xb3\xceS\xba$\xf6\x10\xe9\x16L\x00\xf4[ \x03v-/iZJ\xcc\xc6\xa0Lx\xa5\xa0\x19#H\x84\x00\x00\x000\x0b\xafne\xe4\x06\xae\xe5<\xd9,\xe0h\xe9J\xf2g\xe2\x8a\x88\x88\n\xf4\xb9T\xde'\xf9KJe\t\x9a:\x90o\x18\x8f\x97\xfc5?\xfe\x9e\xd68f\xa7"  # noqa: E501
    )
    packets = list(c2http.iter_recover_http(raw_http))
    assert len(packets) == 2
    assert packets[0].callback == BeaconCallback.CALLBACK_ERROR
    assert packets[1].callback == BeaconCallback.CALLBACK_PENDING


def test_c2http_get_transform_for_http(bconfig):
    c2http = C2Http(bconfig, rsa_private_key=rsa_private)
    assert c2http.get_transform_for_http(http_request_checkin) == c2http.transform_get
    assert c2http.get_transform_for_http(http_response_task_file_list) == c2http.transform_response


def test_c2http_get_transform_for_http_unknown_request(bconfig):
    c2http = C2Http(bconfig, rsa_private_key=rsa_private)
    raw_http = b"GET /testing1234 HTTP/1.1\r\nHost: 127.0.0.1\r\n\n\n"
    request = parse_raw_http(raw_http)
    with pytest.raises(ValueError, match="Possible unrelated HTTP Request or Response, .*"):
        c2http.get_transform_for_http(request)
    with pytest.raises(ValueError, match="Possible unrelated HTTP Request or Response, .*"):
        c2http.get_transform_for_http(raw_http)


def test_c2http_get_transform_for_http_unknown_response(bconfig):
    c2http = C2Http(bconfig, rsa_private_key=rsa_private)
    raw_http = b"HTTP/1.1 200 OK\r\nHost: 127.0.0.1\r\n\n\ndatagoeshere"
    response = parse_raw_http(raw_http)
    assert c2http.get_transform_for_http(response) == c2http.transform_response
    assert c2http.get_transform_for_http(raw_http) == c2http.transform_response


def test_beaconmetadata_set_membership():
    metadata_set = set()
    m1 = BeaconMetadata(magic=0xBEEF, pid=0x12345, info=b"testing")
    m2 = BeaconMetadata(magic=0xBEEF, pid=0x12345, info=b"testing")
    m3 = BeaconMetadata(magic=0xBEEF, pid=0x12345, info=b"12345")
    metadata_set.add(m1)
    assert list(m1._values.items()) == list(m2._values.items())
    assert hash(m1) == hash(m2)
    assert m1 == m2
    assert m2 in metadata_set
    assert m3 not in metadata_set


def test_encrypt_metadata_info_too_large():
    priv = RSA.generate(bits=1024)
    metadata = BeaconMetadata(magic=0xBEEF, pid=0x12345, info=b"A" * 100)
    with pytest.raises(ValueError, match="Plaintext is too long."):
        encrypt_metadata(metadata, priv.public_key())


def test_encrypted_packet_raise_for_signature(c2http):
    enc_packet = EncryptedPacket(b"foo", b"AAAA")
    with pytest.raises(ValueError, match="Invalid HMAC signature, expected .* got 41414141"):
        enc_packet.raise_for_signature(c2http.hmac_key)


def test_beacon_keys_init_aes_only():
    keys = BeaconKeys(b"A" * 16)
    assert keys.aes_key == b"A" * 16
    assert keys.hmac_key is None
    assert keys.iv == BeaconKeys.DEFAULT_AES_IV


def test_beacon_keys_init_aes_and_hmac_only():
    keys = BeaconKeys(b"A" * 16, b"B" * 16)
    assert keys.aes_key == b"A" * 16
    assert keys.hmac_key == b"B" * 16
    assert keys.iv == BeaconKeys.DEFAULT_AES_IV


def test_beacon_keys_init_aes_hmac_and_iv():
    keys = BeaconKeys(b"A" * 16, b"B" * 16, b"C" * 16)
    assert keys.aes_key == b"A" * 16
    assert keys.hmac_key == b"B" * 16
    assert keys.iv == b"C" * 16


def test_encrypt_packet():
    msg = b"hello world"
    keys = BeaconKeys.from_aes_rand(b"random")
    packet = encrypt_packet(msg, **keys._asdict())
    packet.raise_for_signature(keys.hmac_key)

    ciphertext = encrypt_data(msg, keys.aes_key, keys.iv)
    assert packet.ciphertext == ciphertext

    signature = hmac.new(keys.hmac_key, ciphertext, "sha256").digest()[:16]
    assert packet.signature == signature

    plaintext = decrypt_packet(packet, **keys._asdict())
    assert plaintext == b"hello worldAAAAA"
    assert plaintext == pad(msg)

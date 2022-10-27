import random
import time

import pytest
from unittest.mock import patch, PropertyMock
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Request, Response
from Crypto.PublicKey import RSA

from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.c2profile import C2Profile
from dissect.cobaltstrike.c2 import decrypt_metadata, encrypt_packet, parse_raw_http, decrypt_packet
from dissect.cobaltstrike.client import (
    CallbackDebugMessage,
    HttpBeaconClient,
    C2Data,
    TaskPacket,
    CallbackPacket,
    BeaconCommand,
    BeaconCallback,
    random_computer_name,
)


@pytest.fixture
def task_file_list_packet():
    task = TaskPacket()
    task.epoch = int(time.time())
    task.total_size = 19
    task.command = BeaconCommand.COMMAND_FILE_LIST
    task.data = b"\x00\x00\x00\xba\x00\x00\x00\x03.\\*"
    task.size = len(task.data)
    task.total_size = task.size + 8
    return task


def werkzeug_request_to_raw_http(request: Request) -> bytes:
    """Convert a werkzeug Request object to a raw HTTP request as bytes."""
    status_line = b" ".join(
        [
            request.method.encode(),
            request.path.encode() + b"?" + request.query_string,
            request.environ["SERVER_PROTOCOL"].encode(),
        ]
    )
    headers = b"\r\n".join([f"{key}: {value}".encode() for (key, value) in request.headers.items()])
    return b"\r\n".join([status_line, headers]) + b"\r\n\r\n" + request.data


def test_non_http_beacon(dns_beacon_bconfig):
    client = HttpBeaconClient()
    with pytest.raises(ValueError, match="Not a HTTP or HTTPS beacon.*"):
        client.run(bconfig=dns_beacon_bconfig, sleeptime=0, dry_run=True)


def test_random_computer_name():
    random.seed(1337)
    assert random_computer_name() == "WINDOWS-8XKVYXT"
    assert random_computer_name(username="user") == "USER-PC"
    assert random_computer_name(username="user") == "DESKTOP-XG1ZE6W"


@pytest.mark.parametrize(
    ("beacon_id"),
    [
        0x7FFFFFFF + 1,
        0xFFFFFFFF,
        -1,
    ],
)
def test_invalid_beacon_id(beacon_x86_bconfig, beacon_id):
    client = HttpBeaconClient()
    with pytest.raises(ValueError, match="^beacon_id must be less or equal than 2147483647$"):
        client.run(bconfig=beacon_x86_bconfig, beacon_id=beacon_id, dry_run=True)


@pytest.mark.parametrize(
    ("beacon_id", "expected_beacon_id"),
    [
        (3, 2),
        (9, 8),
        (4, 4),
        (1, 0),
        (2, 2),
        (0, 0),
        (0x7FFFFFFF, 0x7FFFFFFE),
    ],
)
def test_valid_beacon_id(beacon_x86_bconfig, beacon_id, expected_beacon_id):
    client = HttpBeaconClient()
    client.run(bconfig=beacon_x86_bconfig, beacon_id=beacon_id, dry_run=True)
    assert client.beacon_id == expected_beacon_id


@pytest.mark.parametrize(
    ("fixture_name"),
    [
        "beacon_x86_bconfig",
        "beacon_x64_bconfig",
        "beacon_custom_xorkey_bconfig",
        "c2test_beacon_bconfig",
    ],
)
def test_client_get_task(request, task_file_list_packet, fixture_name, httpserver: HTTPServer):
    client = HttpBeaconClient()
    bconfig: BeaconConfig = request.getfixturevalue(fixture_name)
    c2profile = C2Profile.from_beacon_config(bconfig)

    # mock the public key in the beacon with our own RSA key pair so we can decrypt the metadata
    with patch.object(BeaconConfig, "public_key", new_callable=PropertyMock) as mock_public_key:
        priv = RSA.generate(bits=1024)
        mock_public_key.return_value = priv.public_key().export_key("DER")
        client.run(bconfig=bconfig, sleeptime=0, dry_run=True, domain="127.0.0.1", port=httpserver.port, scheme="http")

    def GET_handler(request: Request) -> Response:
        assert request.method == c2profile.properties["http-get.verb"].pop()
        assert request.path == c2profile.properties["http-get.uri"].pop()
        assert request.headers.get("User-Agent") == c2profile.properties["useragent"].pop()
        for (header, value) in c2profile.properties.get("http-get.client.header", {}):
            assert request.headers.get(header) == value

        # recover the GET request from the client
        raw_http = werkzeug_request_to_raw_http(request)
        http_request = parse_raw_http(raw_http)
        c2data = client.c2http.transform_get.recover(http_request)
        assert c2data.metadata is not None
        assert c2data.id is None
        assert c2data.output is None

        # decrypt metadata
        metadata = decrypt_metadata(c2data.metadata, priv)
        assert metadata
        assert metadata.magic == 0xBEEF
        assert metadata.bid == client.beacon_id

        # send back a HTTP Response with our Task
        packet = encrypt_packet(task_file_list_packet.dumps(), *client.c2http.beacon_keys)
        http = client.c2http.transform_response.transform(C2Data(output=packet.ciphertext + packet.signature))
        return Response(response=http.body)

    # We expect a GET to get_uri
    httpserver.expect_request(client.get_uri, method=client.get_verb.decode()).respond_with_handler(GET_handler)

    # let the client retrieve a task via HTP.
    task = client.get_task()
    httpserver.check_assertions()
    httpserver.check_handler_errors()

    # check received task attributes
    assert task
    assert task.epoch == task_file_list_packet.epoch
    assert task.command == task_file_list_packet.command
    assert task.data == task_file_list_packet.data


@pytest.mark.parametrize(
    ("fixture_name"),
    [
        "beacon_x86_bconfig",
        "beacon_x64_bconfig",
        "beacon_custom_xorkey_bconfig",
        "c2test_beacon_bconfig",
    ],
)
def test_client_post_callback(request, fixture_name, httpserver: HTTPServer):
    client = HttpBeaconClient()
    bconfig: BeaconConfig = request.getfixturevalue(fixture_name)
    c2profile = C2Profile.from_beacon_config(bconfig)

    client.run(bconfig=bconfig, sleeptime=0, dry_run=True, domain="127.0.0.1", port=httpserver.port, scheme="http")

    def POST_handler(request: Request):
        assert request.method == c2profile.properties["http-post.verb"].pop()
        assert request.path == c2profile.properties["http-post.uri"].pop()
        assert request.headers.get("User-Agent") == c2profile.properties["useragent"].pop()
        for (header, value) in c2profile.properties["http-post.client.header"]:
            assert request.headers.get(header) == value

        # recover the POST request by the client
        raw_http = werkzeug_request_to_raw_http(request)
        # print(raw_http)
        http_request = parse_raw_http(raw_http)
        c2data = client.c2http.transform_submit.recover(http_request)

        # check for our beacon id
        assert c2data.id == str(client.beacon_id).encode()

        # decrypt callback data
        keys = client.c2http.beacon_keys
        for enc_packet in c2data.iter_encrypted_packets():
            data = decrypt_packet(enc_packet, keys.aes_key, keys.hmac_key)
            packet = CallbackPacket(data)
            assert packet.callback == BeaconCallback.CALLBACK_ERROR
            assert b"hello" in packet.data

        # response to POST are ignored by the client
        return Response(response=b"not checked")

    # We expect a POST to submit_uri
    httpserver.expect_request(client.submit_uri, method=client.submit_verb.decode()).respond_with_handler(POST_handler)

    # we send a CallbackDebugMessage as callback data.
    client.send_callback(*CallbackDebugMessage("hello"))

    httpserver.check_assertions()
    httpserver.check_handler_errors()


def test_status_error(beacon_x86_bconfig, httpserver: HTTPServer, caplog):
    client = HttpBeaconClient()
    bconfig: BeaconConfig = beacon_x86_bconfig

    client.run(bconfig=bconfig, sleeptime=0, dry_run=True, domain="127.0.0.1", port=httpserver.port, scheme="http")

    httpserver.expect_request(client.submit_uri, method=client.submit_verb.decode()).respond_with_response(
        Response(b"404 not found", status=404)
    )
    httpserver.expect_request(client.get_uri, method=client.get_verb.decode()).respond_with_response(
        Response(b"500 error", status=500)
    )

    client.get_task()
    assert "HttpStatusError, response 500 while requesting URL" in caplog.text

    client.send_callback(*CallbackDebugMessage("hello"))
    assert "HttpStatusError, response 404 while requesting URL" in caplog.text

    httpserver.check_assertions()
    httpserver.check_handler_errors()


def test_request_error(beacon_x86_bconfig, httpserver: HTTPServer, caplog):
    client = HttpBeaconClient()
    bconfig: BeaconConfig = beacon_x86_bconfig

    # test TLS request to plain HTTP server -> ConnectError with SSL error
    client.run(bconfig=bconfig, sleeptime=0, dry_run=True, domain="127.0.0.1", port=httpserver.port, scheme="https")

    caplog.clear()
    client.get_task()
    assert "ConnectError('[SSL: WRONG_VERSION_NUMBER] wrong version number" in caplog.text

    caplog.clear()
    client.send_callback(*CallbackDebugMessage("hello"))
    assert "ConnectError('[SSL: WRONG_VERSION_NUMBER] wrong version number" in caplog.text

    # test connecton to port that has no webserver running on -> ConnectError with connection refused
    client.run(bconfig=bconfig, sleeptime=0, dry_run=True, domain="127.0.0.1", port=0)

    caplog.clear()
    client.get_task()
    assert "Connection refused" in caplog.text

    caplog.clear()
    client.send_callback(*CallbackDebugMessage("hello"))
    assert "Connection refused" in caplog.text

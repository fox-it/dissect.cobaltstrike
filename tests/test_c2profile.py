from dissect.cobaltstrike import c2profile
from dissect.cobaltstrike import beacon


C2PROFILE_SOURCE = """
set jitter "100";

http-get {
    set uri "/dissect/cobaltstrike";

    client {
        header "Accept-Encoding" "*/*";

        metadata {
            mask;
            netbios;
            header "Cookie";
        }
    }
}
"""


def test_c2profile_parser():
    profile = c2profile.C2Profile.from_text(C2PROFILE_SOURCE)
    props = profile.as_dict()
    assert props["jitter"] == ["100"]
    assert props["http-get.uri"] == ["/dissect/cobaltstrike"]
    assert props["http-get.client.header"] == [("Accept-Encoding", "*/*")]
    assert props["http-get.client.metadata"] == [
        "mask",
        "netbios",
        ("header", b"Cookie"),
    ]
    assert profile.properties == profile.as_dict()
    assert str(profile) == profile.as_text()


def test_c2profile_generator():
    profile = c2profile.C2Profile()
    profile.set_option("jitter", "100")
    profile.set_config_block(
        "http_get",
        c2profile.HttpGetBlock(
            uri="/dissect/cobaltstrike",
            client=c2profile.HttpOptionsBlock(
                header=[("Accept-Encoding", "*/*")],
                metadata=c2profile.DataTransformBlock(
                    steps=["mask", "netbios", ("header", b"Cookie")],
                ),
            ),
        ),
    )
    assert profile.properties["jitter"] == ["100"]
    assert profile.properties["http-get.uri"] == ["/dissect/cobaltstrike"]
    assert profile.properties["http-get.client.header"] == [("Accept-Encoding", "*/*")]
    assert profile.properties["http-get.client.metadata"] == [
        "mask",
        "netbios",
        ("header", b"Cookie"),
    ]


def test_value_to_string():
    val = b"\xCA\xFE\xBA\xBE"
    assert c2profile.value_to_string(val) == '"\\xca\\xfe\\xba\\xbe"'
    val = b"\x00\x22\x27"
    assert c2profile.value_to_string(val) == '"\\x00\\"\'"'


def test_string_conversions():
    string = "\"\\x00\\\"'''test\""
    token = c2profile.Token("STRING", string)
    bstring = c2profile.string_token_to_bytes(token)
    assert bstring == b"\x00\"'''test"
    assert c2profile.value_to_string(bstring) == string


def test_profile_string_escaping():
    source = r"""
    http-get {
        server {
            output {
                append "https\u003a\u002f\u002foffice.net\u003a443\u002fwv\u002fs\u002f1033\u002fprogress16.gif";
                append "double escaped \\u1234 unicode";
                append "double escaped \\xff hex";
                append "\u0050wned \xff\x00\xbb";
                append "H\x65x";
                append "escaped chars \r\n\t\\ \"foo\" \'bar\' 'test'";
                append "mw-redirectedfrom>ￂﾠￂﾠ(Redirected from <a href=/w/";
                print;
            }
        }
    }
    """
    profile = c2profile.C2Profile.from_text(source)
    assert profile.properties["http-get.server.output"] == [
        (
            "append",
            b"https://office.net:443/wv/s/1033/progress16.gif",
        ),
        ("append", b"double escaped \\u1234 unicode"),
        ("append", b"double escaped \\xff hex"),
        ("append", b"Pwned \xff\x00\xbb"),
        ("append", b"Hex"),
        ("append", b"escaped chars \r\n\t\\ \"foo\" 'bar' 'test'"),
        ("append", b"mw-redirectedfrom>\xc2\xa0\xc2\xa0(Redirected from <a href=/w/"),
        "print",
    ]


def test_profile_as_dict():
    profile = c2profile.C2Profile()
    assert profile.as_dict() == {}
    assert len(profile.properties) == 0
    assert profile.properties.get("nonexisting", None) is None

    profile.set_option("jitter", "9000")
    print(profile.tree)
    profile.set_option("useragent", "Mozilla")
    # profile.set_config_block("stage", c2profile.StageBlock(
    #     string=["Hello", b"\x90\x90\x90"]
    # ))
    assert profile.properties["jitter"] == ["9000"]
    assert profile.properties["useragent"] == ["Mozilla"]
    # assert list(profile.properties.keys()) == ["jitter", "useragent", "stage.string"]
    assert dict(profile.properties.items()) == {
        "jitter": ["9000"],
        "useragent": ["Mozilla"],
        # "stage.string": [b"Hello", b"\x90\x90\x90"],
    }


def test_profile_stage_string():
    source = r"""
    set jitter "9000";
    http-config {
        header "foo" "bar";
    }
    stage {
        string "hello";
        string "world";

        stringw "foo";
        stringw "bar";
    }
    """
    profile = c2profile.C2Profile.from_text(source)
    for k, v in profile.properties.items():
        print(k, v)
    print(profile.tree)
    print(profile.tree.pretty())


def test_profile_from_path(tmpdir):
    p = tmpdir.join("c2.profile")
    p.write(C2PROFILE_SOURCE)

    profile = c2profile.C2Profile.from_path(p)
    props = profile.properties
    assert props["http-get.uri"] == ["/dissect/cobaltstrike"]


def test_process_inject():
    config = r"""
    process-inject {
        # set how memory is allocated in a remote process
        set allocator "VirtualAllocEx";

        # shape the memory characteristics and content
        set min_alloc   "16384";
        set startrwx    "true";
        set userwx      "false";

        transform-x86 {
            prepend "\x90\x90";
        }

        transform-x64 {
            # transform x64 injected content
        }

        # determine how to execute the injected code
        execute {
            CreateThread "ntdll.dll!RtlUserThreadStart";
            SetThreadContext;
            RtlCreateUserThread;
        }
    }
    """
    profile = c2profile.C2Profile.from_text(config)
    assert profile.properties["process-inject.allocator"] == ["VirtualAllocEx"]
    assert profile.properties["process-inject.startrwx"] == ["true"]
    assert profile.properties["process-inject.userwx"] == ["false"]
    assert profile.properties["process-inject.transform-x86"] == [("prepend", b"\x90\x90")]
    assert profile.properties["process-inject.execute"] == [
        ("CreateThread", b"ntdll.dll!RtlUserThreadStart"),
        "SetThreadContext",
        "RtlCreateUserThread",
    ]

    profile2 = c2profile.C2Profile()
    profile2.set_config_block(
        "process_inject",
        c2profile.ProcessInjectBlock(
            allocator="VirtualAllocEx",
            min_alloc="16384",
            startrwx="true",
            userwx="false",
            transform_x86=c2profile.StageTransformBlock(prepend=b"\x90\x90"),
            transform_x64=c2profile.StageTransformBlock(),
            execute=c2profile.ExecuteOptionsBlock(
                createthread_special=b"ntdll.dll!RtlUserThreadStart",
                setthreadcontext=True,
                rtlcreateuserthread=True,
            ),
        ),
    )
    assert profile.tree == profile2.tree
    assert profile.as_text() == profile2.as_text()
    assert profile.as_dict() == profile2.as_dict()


def test_execute_options_block():
    a = c2profile.ExecuteOptionsBlock(
        createthread_special=b"ntdll.dll!RtlUserThreadStart+0x1000",
        setthreadcontext=True,
        ntqueueapcthread_s=True,
        createremotethread_special=b"kernel32.dll!LoadLibraryA+0x1000",
        rtlcreateuserthread=True,
    )
    b = c2profile.ExecuteOptionsBlock.from_execute_list(
        [
            ("CreateThread", b"ntdll.dll!RtlUserThreadStart+0x1000"),
            "SetThreadContext",
            "NtQueueApcThread-s",
            ("CreateRemoteThread", b"kernel32.dll!LoadLibraryA+0x1000"),
            "RtlCreateUserThread",
        ]
    )
    assert a.tree == b.tree


def test_c2profile_from_beacon(beacon_x86_file):
    bconfig = beacon.BeaconConfig.from_file(beacon_x86_file)
    profile = c2profile.C2Profile.from_beacon_config(bconfig)
    assert profile.properties["http-get.uri"] == ["/favicon.css"]
    assert profile.properties["http-get.client.header"] == [("Connection", "close"), ("Accept-Language", "en-US")]
    assert profile.properties["http-post.client.id"] == [
        "base64",
        ("prepend", b"__session__id="),
        ("header", b"Cookie"),
    ]


def test_c2profile_no_empty_blocks(beacon_x86_file):
    bconfig = beacon.BeaconConfig.from_file(beacon_x86_file)
    profile = c2profile.C2Profile.from_beacon_config(bconfig)
    assert "dns-beacon {" not in str(profile)


def test_c2profile_dns_beacon(dns_beacon_file):
    bconfig = beacon.BeaconConfig.from_file(dns_beacon_file, xor_keys=[b"\xaf"])
    profile = c2profile.C2Profile.from_beacon_config(bconfig)

    profile.properties["dns-beacon.dns_idle"] == ["19.7.91.241"]
    profile.properties["dns-beacon.maxdns"] == ["251"]
    profile.properties["dns-beacon.beacon"] == ["smtp."]
    profile.properties["dns-beacon.get_A"] == ["up."]
    profile.properties["dns-beacon.get_AAAA"] == ["box."]
    profile.properties["dns-beacon.get_TXT"] == ["lantern."]
    profile.properties["dns-beacon.put_metadata"] == ["test."]
    profile.properties["dns-beacon.put_output"] == ["answer."]

    assert "dns-beacon {" in str(profile)
    assert 'set beacon "smtp.";' in str(profile)

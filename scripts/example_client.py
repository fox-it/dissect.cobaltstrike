#!/usr/bin/env python3
#
# Example beacon client
#
# Run with:
#  $ python3 example_client.py --help
#
# Recommended to do a dry run first to see how it will connect using which parameters:
#  $ python3 example_client.py <beacon_file> -n
#
# Then run it for real in verbose mode:
#  $ python3 example_client.py <beacon_file> -v
#
from io import BytesIO
import textwrap

from dissect.cobaltstrike.client import HttpBeaconClient, BeaconCallback, BeaconCommand, parse_commandline_options
from dissect.cobaltstrike.client import CallbackOutputMessage
from dissect.cobaltstrike.utils import p32be, u32be

client = HttpBeaconClient()


@client.handle(None)
def on_empty_task(task):
    client.logger.debug("Received empty task.")


@client.catch_all()
def catch_all(task):
    orly = "\n".join(
        [
            ",___,",
            "{O,o}",
            "|)``)",
            "O RLY?",
            "",
        ]
    )
    return CallbackOutputMessage(textwrap.indent(orly, "\t"))


@client.handle(BeaconCommand.COMMAND_FILE_LIST)
def on_file_list(task):
    # Parse task data for file listing
    with BytesIO(task.data) as data:
        req_no = u32be(data.read(4))
        size = u32be(data.read(4))
        folder = data.read(size).decode()

    # Create file list response buffer
    buffer = "\n".join(
        [
            folder,
            "{type}\t{size}\t{date}\t{name}".format(type="D", size=0, date="04/10 2022 13:33:37", name="."),
            "{type}\t{size}\t{date}\t{name}".format(type="D", size=0, date="04/10 2022 13:33:37", name=".."),
            "{type}\t{size}\t{date}\t{name}".format(type="D", size=0, date="04/10 2022 13:33:37", name="srsly?"),
            "{type}\t{size}\t{date}\t{name}".format(type="F", size=36, date="04/10 2022 13:33:37", name="flag.txt"),
        ]
    )

    # <request_number>|buffer|<zero termination>
    buffer = p32be(req_no) + buffer.encode() + p32be(0)
    return BeaconCallback.CALLBACK_PENDING, buffer


@client.handle(BeaconCommand.COMMAND_DOWNLOAD)
def on_download(task):
    # from https://github.com/desaster/kippo
    nowai = "\n".join(
        [
            "  ___ ",
            " {o,o}",
            " (__(|",
            ' -"-"-',
            "NO WAI!",
            "",
        ]
    )
    fid = 100
    size = len(nowai)
    file_name = b"flag.txt"
    client.send_callback(BeaconCallback.CALLBACK_FILE, p32be(fid) + p32be(size) + file_name + p32be(0))
    client.send_callback(BeaconCallback.CALLBACK_FILE_WRITE, p32be(fid) + nowai.encode() + p32be(0))
    client.send_callback(BeaconCallback.CALLBACK_FILE_CLOSE, p32be(fid) + p32be(0))


@client.handle(BeaconCommand.COMMAND_SLEEP)
def on_sleep(task):
    with BytesIO(task.data) as data:
        client.sleeptime = u32be(data.read(4))
        client.jitter = u32be(data.read(4))
    client.logger.info("Set new sleeptime: %u, jitter: %u", client.sleeptime, client.jitter)


@client.handle(BeaconCommand.COMMAND_PWD)
def on_pwd(task):
    cwd = f"C:\\Users\\{client.user}\\Documents\\"
    return BeaconCallback.CALLBACK_PWD, cwd.encode() + p32be(0)


if __name__ == "__main__":
    args, options = parse_commandline_options(
        defaults=dict(
            user="O RLY?",
            computer="YA RLY",
        )
    )
    client.run(**options)

A Minimal Beacon Client
-----------------------

This tutorial shows how to implement your own minimal beacon client that can handle tasks and send custom responses.

While the tool :doc:`beacon-client <../tools/beacon-client>` is already a fully working client that can connect to a
Team Server given a beacon payload, it does not handle any received tasks.
While this is very useful for testing and monitoring, it might be useful to have a client that can handle tasks and
send custom callback responses back to the Team Server.

We can make our own custom beacon client by using the ``dissect.cobaltstrike.client`` module.
Currently only the HTTP(s) protocol is supported, so DNS beacons are not yet supported.

See also :doc:`scripts/example_client.py <../scripts/example_client>` for a more detailed implemented client.

Here is an short example client that replies to the Team Server with a Debug message when a ``ls`` command is executed:

.. code-block:: python

    from dissect.cobaltstrike.client import HttpBeaconClient, BeaconCommand, TaskPacket
    from dissect.cobaltstrike.client import parse_commandline_options
    from dissect.cobaltstrike.client import CallbackDebugMessage

    client = HttpBeaconClient()

    @client.handle(BeaconCommand.COMMAND_FILE_LIST)
    def handle_file_list(task: TaskPacket):
        return CallbackDebugMessage("hello world")

    args, options = parse_commandline_options()
    client.run(**options)

To break down the script, we first import the classes and functions that we use.
Then we create a new :class:`~dissect.cobaltstrike.client.HttpBeaconClient` instance called ``client``.

Next we define the function ``handle_file_list`` that will be called when a ``COMMAND_FILE_LIST`` command is
tasked by the Team Server. For a complete list of `COMMANDS` you can refer to :class:`~dissect.cobaltstrike.c_c2.BeaconCommand`.

The ``@client.handle`` decorator is used to register this function as the handler.

The handler function must accept a single argument which is a :class:`~dissect.cobaltstrike.c_c2.TaskPacket` object and
is a simple wrapper around a ``dissect.cstruct`` instance with the following structure:

.. literalinclude:: ../../dissect/cobaltstrike/c_c2.py
        :start-at: typedef struct TaskPacket
        :end-at: };
        :language: c

The ``task.data`` attribute contains the raw Task data bytes, and must still be parsed if you want to do anything with it.
Currently you need to parse this manually as there are many different Tasks and they all have a different structure.

Here is an example on how to parse a ``COMMAND_FILE_LIST`` TaskPacket:

.. code-block:: python

    from io import BytesIO
    from dissect.cobaltstrike.utils import u32be

    @client.handle(BeaconCommand.COMMAND_FILE_LIST)
    def handle_file_list(task):
        # Parse task data for file listing, which is structured as:
        #
        # |<request_number>|<size_of_folder>|<folder>|
        with BytesIO(task.data) as data:
            req_no = u32be(data.read(4))
            size = u32be(data.read(4))
            folder = data.read(size).decode()

        # Return a debug message that prints which folder was requested for `ls`.
        return CallbackDebugMessage(f"You requested to list files in folder: {folder}")

Instead of using the ``@client.handle`` decorator to create task handlers you can also
subclass :class:`~dissect.cobaltstrike.client.HttpBeaconClient` and adding your own handlers
by defining a ``on_<command>`` method:

.. code-block:: python

    from io import BytesIO

    from dissect.cobaltstrike.client import HttpBeaconClient, TaskPacket
    from dissect.cobaltstrike.client import parse_commandline_options
    from dissect.cobaltstrike.client import CallbackDebugMessage
    from dissect.cobaltstrike.utils import u32be

    class EchoClient(HttpBeaconClient):
        def on_sleep(self, task: TaskPacket):
            with BytesIO(task.data) as data:
                self.sleeptime = u32be(data.read(4))
                self.jitter = u32be(data.read(4))
            return CallbackDebugMessage(
                f"Set new sleeptime: {self.sleeptime}, jitter: {self.jitter}"
            )

        def on_catch_all(self, task: TaskPacket):
            if task is None:
                return
            return CallbackDebugMessage(f"Received {task}")

    args, options = parse_commandline_options()
    EchoClient().run(**options)

"""
Structure definitions and classes for dealing with Cobalt Strike C2 packets.
Mainly used by :mod:`dissect.cobaltstrike.c2`.
"""
from enum import IntEnum

from dissect import cstruct


class BeaconCommand(IntEnum):
    COMMAND_SPAWN = 1
    COMMAND_SHELL = 2
    COMMAND_DIE = 3
    COMMAND_SLEEP = 4
    COMMAND_CD = 5
    COMMAND_KEYLOG_START = 6
    COMMAND_NOOP = 6
    COMMAND_KEYLOG_STOP = 7
    COMMAND_CHECKIN = 8
    COMMAND_INJECT_PID = 9
    COMMAND_UPLOAD = 10
    COMMAND_DOWNLOAD = 11
    COMMAND_EXECUTE = 12
    COMMAND_SPAWN_PROC_X86 = 13
    COMMAND_CONNECT = 14
    COMMAND_SEND = 15
    COMMAND_CLOSE = 16
    COMMAND_LISTEN = 17
    COMMAND_INJECT_PING = 18
    COMMAND_CANCEL_DOWNLOAD = 19
    COMMAND_PIPE_ROUTE = 22
    COMMAND_PIPE_CLOSE = 23
    COMMAND_PIPE_REOPEN = 24
    COMMAND_TOKEN_GETUID = 27
    COMMAND_TOKEN_REV2SELF = 28
    COMMAND_TIMESTOMP = 29
    COMMAND_STEAL_TOKEN = 31
    COMMAND_PS_LIST = 32
    COMMAND_PS_KILL = 33
    COMMAND_PSH_IMPORT = 37
    COMMAND_RUNAS = 38
    COMMAND_PWD = 39
    COMMAND_JOB_REGISTER = 40
    COMMAND_JOBS = 41
    COMMAND_JOB_KILL = 42
    COMMAND_INJECTX64_PID = 43
    COMMAND_SPAWNX64 = 44
    COMMAND_INJECT_PID_PING = 45
    COMMAND_INJECTX64_PID_PING = 46
    COMMAND_PAUSE = 47
    COMMAND_LOGINUSER = 49
    COMMAND_LSOCKET_BIND = 50
    COMMAND_LSOCKET_CLOSE = 51
    COMMAND_STAGE_PAYLOAD = 52
    COMMAND_FILE_LIST = 53
    COMMAND_FILE_MKDIR = 54
    COMMAND_FILE_DRIVES = 55
    COMMAND_FILE_RM = 56
    COMMAND_STAGE_PAYLOAD_SMB = 57
    COMMAND_WEBSERVER_LOCAL = 59
    COMMAND_ELEVATE_PRE = 60
    COMMAND_ELEVATE_POST = 61
    COMMAND_JOB_REGISTER_IMPERSONATE = 62
    COMMAND_SPAWN_POWERSHELLX86 = 63
    COMMAND_SPAWN_POWERSHELLX64 = 64
    COMMAND_INJECT_POWERSHELLX86_PID = 65
    COMMAND_INJECT_POWERSHELLX64_PID = 66
    COMMAND_UPLOAD_CONTINUE = 67
    COMMAND_PIPE_OPEN_EXPLICIT = 68
    COMMAND_SPAWN_PROC_X64 = 69
    COMMAND_JOB_SPAWN_X86 = 70
    COMMAND_JOB_SPAWN_X64 = 71
    COMMAND_SETENV = 72
    COMMAND_FILE_COPY = 73
    COMMAND_FILE_MOVE = 74
    COMMAND_PPID = 75
    COMMAND_RUN_UNDER_PID = 76
    COMMAND_GETPRIVS = 77
    COMMAND_EXECUTE_JOB = 78
    COMMAND_PSH_HOST_TCP = 79
    COMMAND_DLL_LOAD = 80
    COMMAND_REG_QUERY = 81
    COMMAND_LSOCKET_TCPPIVOT = 82
    COMMAND_ARGUE_ADD = 83
    COMMAND_ARGUE_REMOVE = 84
    COMMAND_ARGUE_LIST = 85
    COMMAND_TCP_CONNECT = 86
    COMMAND_JOB_SPAWN_TOKEN_X86 = 87
    COMMAND_JOB_SPAWN_TOKEN_X64 = 88
    COMMAND_SPAWN_TOKEN_X86 = 89
    COMMAND_SPAWN_TOKEN_X64 = 90
    COMMAND_INJECTX64_PING = 91
    COMMAND_BLOCKDLLS = 92
    COMMAND_SPAWNAS_X86 = 93
    COMMAND_SPAWNAS_X64 = 94
    COMMAND_INLINE_EXECUTE = 95
    COMMAND_RUN_INJECT_X86 = 96
    COMMAND_RUN_INJECT_X64 = 97
    COMMAND_SPAWNU_X86 = 98
    COMMAND_SPAWNU_X64 = 99
    COMMAND_INLINE_EXECUTE_OBJECT = 100
    COMMAND_JOB_REGISTER_MSGMODE = 101
    COMMAND_LSOCKET_BIND_LOCALHOST = 102


class BeaconCallback(IntEnum):
    CALLBACK_OUTPUT = 0
    CALLBACK_KEYSTROKES = 1
    CALLBACK_FILE = 2
    CALLBACK_SCREENSHOT = 3
    CALLBACK_CLOSE = 4
    CALLBACK_READ = 5
    CALLBACK_CONNECT = 6
    CALLBACK_PING = 7
    CALLBACK_FILE_WRITE = 8
    CALLBACK_FILE_CLOSE = 9
    CALLBACK_PIPE_OPEN = 10
    CALLBACK_PIPE_CLOSE = 11
    CALLBACK_PIPE_READ = 12
    CALLBACK_POST_ERROR = 13
    CALLBACK_PIPE_PING = 14
    CALLBACK_TOKEN_STOLEN = 15
    CALLBACK_TOKEN_GETUID = 16
    CALLBACK_PROCESS_LIST = 17
    CALLBACK_POST_REPLAY_ERROR = 18
    CALLBACK_PWD = 19
    CALLBACK_JOBS = 20
    CALLBACK_HASHDUMP = 21
    CALLBACK_PENDING = 22
    CALLBACK_ACCEPT = 23
    CALLBACK_NETVIEW = 24
    CALLBACK_PORTSCAN = 25
    CALLBACK_DEAD = 26
    CALLBACK_SSH_STATUS = 27
    CALLBACK_CHUNK_ALLOCATE = 28
    CALLBACK_CHUNK_SEND = 29
    CALLBACK_OUTPUT_OEM = 30
    CALLBACK_ERROR = 31
    CALLBACK_OUTPUT_UTF8 = 32


C2_DEF = """
// Callback data from: Beacon -> Team Server
typedef struct CallbackPacket {
    uint32 counter;
    uint32 size;
    BeaconCallback callback;
    char data[size];
};

// Task from: Team Server -> Beacon
typedef struct TaskPacket {
    uint32 epoch;
    uint32 total_size;
    BeaconCommand command;
    uint32 size;
    char data[size];
};

struct BeaconMetadata {
    uint32 magic;
    uint32 size;
    char aes_rand[16];
    uint16 ansi_cp;     // GetACP
    uint16 oem_cp;      // GetOEMCP
    uint32 bid;
    uint32 pid;
    uint16 port;
    uint8 flag;
    uint8 ver_major;
    uint8 ver_minor;
    uint16 ver_build;
    uint32 ptr_x64;     // for x64 addressing
    uint32 ptr_gmh;     // GetModuleHandle
    uint32 ptr_gpa;     // GetProcAddress
    uint32 ip;
    char info[size - 51];
};
"""
c2struct = cstruct.cstruct(endian=">")


def typedef_for_enum(enum_class: IntEnum, int_type: str = "uint32") -> str:
    """Return C compatible typedef string for `enum_class`."""
    header = f"typedef enum {enum_class.__name__} : {int_type} {{"
    defs = (f"    {e.name} = {e.value}," for e in enum_class)
    footer = "};"
    return "\n".join([header, *defs, footer])


c2struct.load(typedef_for_enum(BeaconCommand))
c2struct.load(typedef_for_enum(BeaconCallback))
c2struct.load(C2_DEF)


# Some wrapper classes for some dissect.cstruct structs, mainly so we can use `isinstance()`
class BeaconMetadata(cstruct.Instance):
    magic: int
    size: int
    aes_rand: bytes
    ansi_cp: int
    oem_cp: int
    bid: int
    pid: int
    port: int
    flag: int
    ver_major: int
    ver_minor: int
    ver_build: int
    ptr_x64: int
    ptr_gmh: int
    ptr_gpa: int
    ip: int
    info: bytes

    def __init__(self, *args, **kwargs):
        instance = c2struct.BeaconMetadata(*args, **kwargs)
        super().__init__(instance._type, instance._values, instance._sizes)

    def __eq__(self, other):
        return self._values == other._values

    def __hash__(self):
        return hash(tuple(self._values.items()))


class CallbackPacket(cstruct.Instance):
    counter: int
    size: int
    callback: BeaconCallback
    data: bytes

    def __init__(self, *args, **kwargs):
        instance = c2struct.CallbackPacket(*args, **kwargs)
        super().__init__(instance._type, instance._values, instance._sizes)

    def __eq__(self, other):
        return self._values == other._values

    def __hash__(self):
        return hash(tuple(self._values.items()))


class TaskPacket(cstruct.Instance):
    epoch: int
    total_size: int
    command: BeaconCommand
    size: int
    data: bytes

    def __init__(self, *args, **kwargs):
        instance = c2struct.TaskPacket(*args, **kwargs)
        super().__init__(instance._type, instance._values, instance._sizes)

    def __eq__(self, other):
        return self._values == other._values

    def __hash__(self):
        return hash(tuple(self._values.items()))

"""
This module contains helper functions for parsing PE files, mainly for extracting Beacon specific PE artifacts.
"""
import io
import logging
from typing import Optional, Tuple, BinaryIO

from dissect import cstruct

logger = logging.getLogger(__name__)

PE_DEF = """
#define IMAGE_FILE_MACHINE_AMD64    0x8664
#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_IA64     0x0200

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME          8

#define IMAGE_DIRECTORY_ENTRY_EXPORT	0
#define IMAGE_DIRECTORY_ENTRY_IMPORT	1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE	2

typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_SECTION_HEADER {
    char    Name[IMAGE_SIZEOF_SHORT_NAME];
    ULONG   VirtualSize;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG   Characteristics;
        ULONG   OriginalFirstThunk;
    } u;
    ULONG   TimeDateStamp;
    ULONG   ForwarderChain;
    ULONG   Name;
    ULONG   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;     // RVA from base of image
    ULONG   AddressOfNames;         // RVA from base of image
    ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY;
"""

pestruct = cstruct.cstruct()
pestruct.load(PE_DEF)

DOSHEADER_X64 = bytes.fromhex("554889e54881")
DOSHEADER_X86 = bytes.fromhex("e8000000005b")


def find_mz_offset(fh: BinaryIO, start_offset: int = 0, maxrange: int = 1024) -> Optional[int]:
    """Find and return the start offset of a valid IMAGE_DOS_HEADER or ``None`` if it cannot be found.

    It uses `IMAGE_DOS_HEADER.e_lfanew` and `IMAGE_FILE_HEADER.Machine` as a constraint.

    Side effects: file handle position due to seeking

    Args:
        fh: file like object
        start_offset: offset to start searching from, None indicates from current file position
        maxrange: how far to search for into the file object

    Returns:
        offset of the start of IMAGE_DOS_HEADER in the file object or ``None`` if it's not found
    """
    start_offset = start_offset if start_offset is not None else fh.tell()
    for offset in range(maxrange):
        fh.seek(start_offset + offset, io.SEEK_SET)
        try:
            mz = pestruct.IMAGE_DOS_HEADER(fh)
            if mz.e_lfanew > 0 and mz.e_lfanew < maxrange:
                fh.seek(start_offset + offset + 4 + mz.e_lfanew)
                image = pestruct.IMAGE_FILE_HEADER(fh)
                if image.Machine in (
                    pestruct.IMAGE_FILE_MACHINE_AMD64,
                    pestruct.IMAGE_FILE_MACHINE_I386,
                ):
                    return start_offset + offset
        except EOFError:
            continue
    return None


def find_compile_stamps(
    fh: BinaryIO, start_offset: int = 0, maxrange: int = 1024
) -> Tuple[Optional[int], Optional[int]]:
    """Find and return a tuple with the `PE compile` and `PE export` timestamps.

    If one or more `TimeDateStamps` are not found it will be returned as ``None`` in the tuple.

    Side effects: file handle position due to seeking

    Args:
        fh: file like object
        start_offset: offset to start searching from, ``None`` indicates from current file position
        maxrange: how far to search for into the file object

    Returns:
        Tuple with ``(IMAGE_FILE_HEADER.TimeDateStamp, IMAGE_EXPORT_DIRECTORY.TimeDateStamp)``.
        Either tuple values can be ``None`` if it's not found.
    """
    mz_offset = find_mz_offset(fh, start_offset=start_offset, maxrange=maxrange)
    if mz_offset is None:
        return (None, None)

    compile_stamp = None
    export_stamp = None
    fh.seek(mz_offset)
    mz = pestruct.IMAGE_DOS_HEADER(fh)
    fh.seek(mz.e_lfanew + mz_offset)
    signature = pestruct.uint32(fh).to_bytes(4, "little")
    logger.debug("PE signature: %r", signature)
    image = pestruct.IMAGE_FILE_HEADER(fh)
    compile_stamp = image.TimeDateStamp
    if image.Machine == pestruct.IMAGE_FILE_MACHINE_AMD64:
        optional_header = pestruct.IMAGE_OPTIONAL_HEADER64(fh)
    else:
        optional_header = pestruct.IMAGE_OPTIONAL_HEADER(fh)
    export_dd = optional_header.DataDirectory[pestruct.IMAGE_DIRECTORY_ENTRY_EXPORT]
    sections = [pestruct.IMAGE_SECTION_HEADER(fh) for _ in range(image.NumberOfSections)]
    ds = None
    for section in sections:
        if section.VirtualAddress <= export_dd.VirtualAddress < (section.VirtualAddress + section.VirtualSize):
            ds = section
            break
    if ds is not None:
        offset = export_dd.VirtualAddress - ds.VirtualAddress + ds.PointerToRawData + mz_offset
        fh.seek(offset)
        export_dir = pestruct.IMAGE_EXPORT_DIRECTORY(fh)
        export_stamp = export_dir.TimeDateStamp
    return (compile_stamp, export_stamp)


def find_magic_mz(fh: BinaryIO, start_offset: int = 0, maxrange: int = 1024) -> Optional[bytes]:
    """Find and returns the MZ header bytes or ``None`` if cannot be found

    Cobalt Strike allows changing the MZ magic header using `magic_mz_x86` or `magic_mz_x64` in the c2 profile.
    This function recovers these bytes.

    Side effects: file handle position due to seeking

    Args:
        fh: file like object
        start_offset: offset to start searching from, None indicates from current file position
        maxrange: how far to search for into the file object

    Returns:
        MZ header bytes or ``None`` if not found.
    """
    mz_offset = find_mz_offset(fh, start_offset=start_offset, maxrange=maxrange)
    if mz_offset is None:
        return None

    fh.seek(mz_offset)
    data = fh.read(256)
    pos = data.find(DOSHEADER_X86)
    pos = data.find(DOSHEADER_X64) if pos == -1 else pos
    if pos >= 0:
        return data[:pos]
    return None


def find_magic_pe(fh: BinaryIO, start_offset: int = 0, maxrange: int = 1024) -> Optional[bytes]:
    """Find and returns the PE header (``magic_pe``) bytes or ``None`` if cannot be found

    Cobalt Strike allows changing the PE magic header using the ``magic_pe`` in the malleable c2 profile.
    This function tries to recovers these bytes.

    Side effects: file handle position due to seeking

    Args:
        fh: file like object
        start_offset: offset to start searching from, None indicates from current file position
        maxrange: how far to search for into the file object

    Returns:
        PE header bytes or ``None`` if not found.
    """
    mz_offset = find_mz_offset(fh, start_offset=start_offset, maxrange=maxrange)
    if mz_offset is None:
        return None

    magic_pe = None
    fh.seek(mz_offset)
    mz = pestruct.IMAGE_DOS_HEADER(fh)
    fh.seek(mz.e_lfanew + mz_offset)
    magic_pe = fh.read(4).rstrip(b"\x00")
    return magic_pe


def find_stage_prepend_append(
    fh: BinaryIO, start_offset: int = 0, maxrange: int = 1024
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Find and return the stage prepend and append bytes as a tuple.

    Cobalt Strike allows prepending and appending extra bytes to the beacon using malleable c2 profile settings.
    This function tries to recover these bytes.

    Side effects: file handle position due to seeking

    Args:
        fh: file like object
        start_offset: offset to start searching from, None indicates from current file position
        maxrange: how far to search for into the file object

    Returns:
        Tuple containing ``(prepend_bytes, append_bytes)``. Either tuple values can be ``None`` if it's not found.
    """
    mz_offset = find_mz_offset(fh, start_offset=start_offset, maxrange=maxrange)
    if mz_offset is None:
        return (None, None)

    prepend = None
    append = None
    if mz_offset > 0:
        fh.seek(0)
        prepend = fh.read(mz_offset)

    logger.debug("stage prepend: %r", prepend)

    fh.seek(mz_offset)
    mz = pestruct.IMAGE_DOS_HEADER(fh)
    fh.seek(mz.e_lfanew + mz_offset + 4)
    image = pestruct.IMAGE_FILE_HEADER(fh)
    if image.Machine == pestruct.IMAGE_FILE_MACHINE_AMD64:
        optional_header = pestruct.IMAGE_OPTIONAL_HEADER64(fh)
    elif image.Machine == pestruct.IMAGE_FILE_MACHINE_I386:
        optional_header = pestruct.IMAGE_OPTIONAL_HEADER(fh)
    else:
        return (prepend, None)

    size = optional_header.SizeOfHeaders
    sections = [pestruct.IMAGE_SECTION_HEADER(fh) for _ in range(image.NumberOfSections)]
    for section in sections:
        size += section.SizeOfRawData

    logger.debug("Total PE size: %u", size)
    fh.seek(mz_offset + size)

    # we limit the append size to 1024, just in case.
    append = fh.read(1024) or None
    logger.debug("stage append: %r", append)

    # remove padding
    if append is not None:
        append = append.rstrip(b"\x00")

    return (prepend, append)


def find_architecture(fh: BinaryIO, start_offset: int = 0, maxrange: int = 1024) -> Optional[str]:
    """Find and return the PE image architecture, either ``"x86"`` or ``"x64"`` or ``None`` if not found.

    It uses `IMAGE_DOS_HEADER.e_lfanew` and `IMAGE_FILE_HEADER.Machine` as a constraint.

    Only `x86` and `x64` are considered, other machine architectures are ignored.

    Side effects: file handle position due to seeking

    Args:
        fh: file like object
        start_offset: offset to start searching from, None indicates from current file position
        maxrange: how far to search for into the file object

    Returns:
        ``"x86"`` or ``"x64"``, ``None`` if not found.
    """
    start_offset = start_offset if start_offset is not None else fh.tell()
    for offset in range(maxrange):
        fh.seek(start_offset + offset, io.SEEK_SET)
        try:
            mz = pestruct.IMAGE_DOS_HEADER(fh)
            if mz.e_lfanew > 0 and mz.e_lfanew < maxrange:
                fh.seek(start_offset + offset + 4 + mz.e_lfanew)
                image = pestruct.IMAGE_FILE_HEADER(fh)
                if image.Machine == pestruct.IMAGE_FILE_MACHINE_AMD64:
                    return "x64"
                elif image.Machine == pestruct.IMAGE_FILE_MACHINE_I386:
                    return "x86"
        except EOFError:
            continue
    return None

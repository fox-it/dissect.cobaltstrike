"""
Structure definitions for dealing with Cobalt Strike obfuscated Beacon stages.
Mainly used by :mod:`dissect.cobaltstrike.obfuscate`.

This functionality was introduced in Cobalt Strike 4.11.
In the c2profile this configured via the ``stage.transform-obfuscate`` setting.

References:
 - https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping
 - https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm#_Toc65482856
 - https://whiteknightlabs.com/2025/05/19/harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion-part-2/
"""

from dissect.cstruct import cstruct

C_OBFUSCATE_DEF = """
enum ObfuscationType : uint32 {
    OBFUSCATION_NONE = 0,
    OBFUSCATION_XOR = 1,
    OBFUSCATION_RC4 = 2,
    OBFUSCATION_BASE64 = 3,
    OBFUSCATION_LZNT1 = 4,
};

// Used in Cobalt Strike 4.11 and 4.11.1
struct StageEvasionSettingsV1 {
    uint16 copy_pe_header;
    uint16 eaf_bypass;
    uint16 rdll_use_syscalls;
    uint32 max_size;                // peak workspace size over the obfuscation chain
    uint32 payload_size;            // StageObfuscateSettings + key + obfuscated payload
};

// Used in Cobalt Strike 4.12
struct StageEvasionSettingsV2 {
    uint16 copy_pe_header;
    uint16 eaf_bypass;
    uint16 rdll_use_syscalls;
    uint16 rdll_use_driploading;
    uint32 rdll_dripload_delay;
    uint32 max_size;                // peak workspace size over the obfuscation chain
    uint32 payload_size;            // StageObfuscateSettings + key + obfuscated payload
};

// This is common for both versions
struct StageObfuscateSettings {
    ObfuscationType obfuscation_type;   // uint32
    uint32 key_size;
    uint32 original_size;               // size after deobfuscation
    uint32 payload_size;                // size of the obfuscated payload (before deobfuscation)
};
"""

c_obfuscate = cstruct(endian="<").load(C_OBFUSCATE_DEF)

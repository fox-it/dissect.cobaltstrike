import "console"
import "math"

rule srt_cobaltstrike_obfuscated_v4_11 {
  meta:
    author      = "Yun Zheng Hu / hu@fox-it.com"
    date        = "2026-01-30"
    version     = "1.0"
    description = "Matches CobaltStrike 4.11 obfuscated payloads"

  condition:
    for any j in (0..0x5000):
    (
      // evasion settings struct
      (
        uint16(j) <= 1  // copy_pe_header
        and
        uint16(j + 2) <= 1  // eaf_bypass
        and
        uint16(j + 4) <= 1  // rdll_use_syscalls
        and
        uint32(j + 10) > 1024  // payload_size
        and
        filesize - j - 14 - uint32(j + 10) >= 0
        and
        filesize - j - 14 - uint32(j + 10) < 1024
      )
      // check max_size, ev.max_size >= max(ob.original_size, ob.payload_size)
      and (
        uint32(j + 8) >= math.max(uint32(j + 26), uint32(j + 22))
      )
      and (
        // ev.payload_size - 16 - ob.key_size == ob.output_size
        (uint32(j + 10) - uint32(j + 18) - 16) == uint32(j + 26)
      )
      // | obf_type (4) | key_size (4) | input_size (4) | output_size (4) |
      // obfuscation type
      and
      (
        uint32(j + 14) <= 4  // none=0, xor=1, rc4=2, base64=3, lznt1=4
      )
      // key_size constraint check
      and (
        uint32(j + 18) >= 8  // min key_size
        and
        uint32(j + 18) <= 2048  // max key_size
        or
        uint32(j + 18) == 0  // key_size can be null if not use
      )
    )
}

rule srt_cobaltstrike_obfuscated_v4_12 {
  meta:
    author      = "Yun Zheng Hu / hu@fox-it.com"
    date        = "2026-01-30"
    version     = "1.0"
    description = "Matches CobaltStrike 4.12 obfuscated payloads"

  condition:
    for any j in (0..0x5000):
    (
      // evasion settings struct
      (
        uint16(j) <= 1  // copy_pe_header
        and
        uint16(j + 2) <= 1  // eaf_bypass
        and
        uint16(j + 4) <= 1  // rdll_use_syscalls
        and
        uint16(j + 6) <= 1  // rdll_use_driploading
        and
        uint32(j + 16) > 1024  // payload_size
        and
        filesize - j - 20 - uint32(j + 16) >= 0
        and
        filesize - j - 20 - uint32(j + 16) < 1024
      )
      // check max_size, ev.max_size >= max(ob.original_size, ob.payload_size)
      and (
        uint32(j + 12) >= math.max(uint32(j + 28), uint32(j + 32))
      )
      and (
        // ev.payload_size - 16 - ob.key_size == ob.output_size
        (uint32(j + 16) - uint32(j + 24) - 16) == uint32(j + 32)
      )
      // | obf_type (4) | key_size (4) | input_size (4) | output_size (4) |
      // obfuscation type
      and
      (
        uint32(j + 20) <= 4  // none=0, xor=1, rc4=2, base64=3, lznt1=4
      )
      // key_size constraint check
      and (
        uint32(j + 24) >= 8  // min key_size
        and
        uint32(j + 24) <= 2048  // max key_size
        or
        uint32(j + 24) == 0  // key_size can be null if not use
      )
    )
}

/// XORENCODED versions

rule srt_cobaltstrike_xorencoded_obfuscated_v4_11 {
  meta:
    author      = "Yun Zheng Hu / hu@fox-it.com"
    date        = "2026-01-30"
    version     = "1.0"
    description = "Matches CobaltStrike 4.12 obfuscated payloads (XORENCODED)"

  condition:
    for any i in (1..0x100):
    (
      (i + 4 < filesize - i - 8) and uint32(i) ^ uint32(i + 4) == filesize - i - 8
      and
      for any j in (0..0x5000):
      (
        // avoid files with a lot of NULL data
        uint32(j) != 0 and uint32(j - 4) != 0
        and
        uint32(j + 4) != 0 and uint32(j - 4) != 0
        and
        // evasion settings
        (
          uint16(j) ^ uint16(j - 4) <= 1  // copy_pe_header
          and
          uint16(j + 2) ^ uint16(j + 2 - 4) <= 1  // eaf_bypass
          and
          uint16(j + 4) ^ uint16(j + 4 - 4) <= 1  // rdll_use_syscalls
          and
          uint32(j + 10) > 1024  // payload_size
        )
        // check max_size, ev.max_size >= max(ob.original_size, ob.payload_size)
        and (
          (uint32(j + 6) ^ uint32(j + 6 - 4)) >= math.max((uint32(j + 22) ^ uint32(j + 22 - 4)), (uint32(j + 26) ^ uint32(j + 26 - 4)))
        )
        // check leftover data (size of 4.11 evasion block: 14 bytes)
        and (
          filesize - j - 14 - (uint32(j + 10) ^ uint32(j + 10 - 4)) >= 0
          and
          filesize - j - 14 - (uint32(j + 10) ^ uint32(j + 10 - 4)) < 2048
        )
        and (
          // ev.payload_size - ob.key_size - 16 == ob.output_size
          ((uint32(j + 10) ^ uint32(j + 10 - 4)) - (uint32(j + 18) ^ uint32(j + 18 - 4)) - 16) == (uint32(j + 26) ^ uint32(j + 26 - 4))
        )
        // | obf_type (4) | key_size (4) | input_size (4) | output_size (4) |
        // obfuscation type
        and
        (
          uint32(j + 14) ^ uint32(j + 14 - 4) <= 4  // none=0, xor=1, rc4=2, base64=3, lznt1=4
        )
        // key_size constraint check
        and (
          uint32(j + 18) ^ uint32(j + 18 - 4) >= 8  // min key_size
          and
          uint32(j + 18) ^ uint32(j + 18 - 4) <= 2048  // max key_size
          or
          uint32(j + 18) ^ uint32(j + 18 - 4) == 0  // key_size can be null if not use
        )
      )
    )
}

rule srt_cobaltstrike_xorencoded_obfuscated_v4_12 {
  meta:
    author      = "Yun Zheng Hu / hu@fox-it.com"
    date        = "2026-01-30"
    version     = "1.0"
    description = "Matches CobaltStrike 4.12 obfuscated payloads (XORENCODED)"

  condition:
    for any i in (1..0x100):
    (
      (i + 4 < filesize - i - 8) and uint32(i) ^ uint32(i + 4) == filesize - i - 8
      and

      for any j in (0..0x5000):
      (
        // evasion settings struct
        (
          uint16(j) ^ uint16(j - 4) <= 1  // copy_pe_header
          and
          uint16(j + 2) ^ uint16(j + 2 - 4) <= 1  // eaf_bypass
          and
          uint16(j + 4) ^ uint16(j + 4 - 4) <= 1  // rdll_use_syscalls
          and
          uint16(j + 6) ^ uint16(j + 6 - 4) <= 1  // rdll_use_driploading
          and
          uint32(j + 16) ^ uint32(j + 16 - 4) > 1024  // payload_size
        )
        // check max_size, ev.max_size >= max(ob.original_size, ob.payload_size)
        and (
          (uint32(j + 12) ^ uint32(j + 12 - 4)) >= math.max((uint32(j + 28) ^ uint32(j + 28 - 4)), (uint32(j + 32) ^ uint32(j + 32 - 4)))
        )
        // check leftover data (size of 4.12 evasion block: 20 bytes)
        and (
          filesize - j - 20 - (uint32(j + 16) ^ uint32(j + 16 - 4)) >= 0
          and
          filesize - j - 20 - (uint32(j + 16) ^ uint32(j + 16 - 4)) < 2048
        )
        and (
          // ev.payload_size - 16 - ob.key_size == ob.output_size
          ((uint32(j + 16) ^ uint32(j + 16 - 4)) - (uint32(j + 24) ^ uint32(j + 24 - 4)) - 16) == (uint32(j + 32) ^ uint32(j + 32 - 4))
        )
        // | obf_type (4) | key_size (4) | input_size (4) | output_size (4) |
        // obfuscation type
        and
        (
          uint32(j + 20) ^ uint32(j + 20 - 4) <= 4  // none=0, xor=1, rc4=2, base64=3, lznt1=4
        )
        // key_size constraint check
        and (
          uint32(j + 24) ^ uint32(j + 24 - 4) >= 8  // min key_size
          and
          uint32(j + 24) ^ uint32(j + 24 - 4) <= 2048  // max key_size
          or
          uint32(j + 24) ^ uint32(j + 24 - 4) == 0  // key_size can be null if not use
        )
      )
    )
}

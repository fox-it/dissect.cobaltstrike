# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-10-01

### Added

- Support for the Cobalt Strike 4.11 `stage.transform-obfuscate` feature,
  deobfuscating beacon payloads obfuscated with combinations of XOR, RC4,
  base64 and lznt1 (`obfuscate.py`, `c_obfuscate`).
- New `stage.py` module to detect and resolve chained beacon stages (obfuscation
  and XOR-decode layers).
- New `normalize.py` module to detect and adapt tampered beacon configurations
  (e.g. modified `SettingsType` enum values) so they can still be parsed, via a
  configurable `Normalizer` pipeline.
- `BeaconConfigBlock` and `BeaconModifications` dataclasses; `BeaconConfig` now
  exposes `obfuscate_settings`, `stages` and `modifications`.
- New `BeaconSetting` values for Cobalt Strike 4.11–4.13 (chunked POST sizes,
  DNS-over-HTTPS, process-injection drip load, check-in delay) and the
  `ObfSetThreadContext` inject executors.
- Version and setting mappings for Cobalt Strike 4.11, 4.12 and 4.13.
- Parsing of `transform-obfuscate` blocks in Malleable C2 profiles
  (grammar + `TransformObfuscateBlock`).
- `beacon-dump` CLI: `--fail-on-error` flag, recursion into directories, and a
  verbose stock-type mismatch warning (`STOCK_TYPE` mapping).
- Additional PE export timestamp for Cobalt Strike 4.10 (#80).
- Documentation example and test coverage for transform-obfuscate beacons.

### Changed

- Rewrote beacon configuration discovery to be payload-first: it searches for the
  RSA encryption OID embedded in `SETTING_PUBKEY` and walks packed TLV settings to
  recover the config start, treating setting index/type values as opaque.
- Support the 0x1800 (V2) configuration patch size used since Cobalt Strike 4.9.
- Improved deprecated-setting disambiguation using the maximum seen setting enum.
- Recover over-long `C2_REQUEST`/`C2_POSTREQ` transform programs.
- The Cobalt Strike version is now only deduced from the PE export timestamp when
  it maps to a known version; from 4.11 onwards the export timestamp is no longer
  present in the beacon.
- `pycryptodome` is now a core dependency; `lark` requires `>= 1.3.1`.
- Updated project dependencies (#82) and cstruct usage (#81).

### Removed

- Dropped support for Python 3.9 (#82).

## [1.2.1] - 2025-03-25

### Added

- Support for beacon guardrails, including definitions and documentation (#73, #75).
- Support for the `SETTING_HTTP_DATA_REQUIRED` beacon setting (#71).
- Support for the `SETTING_DATA_STORE_SIZE` and `SETTING_BEACON_GATE` options (#68).
- Version detection for Cobalt Strike 4.9 and 4.10 (#66), and 4.10.1 (#76).
- Output of `bof_reuse_memory` and `bof_allocator` in the c2profile (#67).
- Beacon version table added to the documentation (#77).

### Fixed

- `BeaconSetting` names with unknown values (#64).

### Changed

- Speed up beacon file reading from zip files in tests (#65).

## [1.2.0] - 2024-10-11

### Changed

- Compatibility with `dissect.cstruct` v4 (#56).
- Updated minimal Python requirement to 3.9 (#58).
- Migrated packaging from setuptools to a full `pyproject.toml` (#61).
- Switched the GitHub workflow to `dissect-ci.yml` and updated GitHub Actions
  and pre-commit checks (#59, #60, #62).
- Pinned `sphinx_rtd_theme >= 2.0` to fix readthedocs (#57).

## [1.1.0] - 2024-09-23

### Added

- Version detection for Cobalt Strike 4.8 (#44) and improved support for
  Cobalt Strike 4.7 and 4.8 (#47).
- Beacon version information printed when running `beacon-dump -v` (#46).

### Changed

- Switched the linter to `ruff` (#50) and added `codespell` to pre-commit (#41).
- Sped up `xor` using pseudo-SIMD and sped up finding non-standard beacon
  XOR keys (#49).
- Improved C2 and client code to better handle certain beacon configs (#48).
- Decode `SETTING_DOMAINS` using latin-1 instead of ascii (#45).

### Fixed

- Pinned `dissect.cstruct < 4.0` for compatibility (#54).

## [1.0.0] - 2022-10-28

### Added

- Support for the beacon client and decrypting traffic from PCAP files (#25).
- New `beacon-artifact` CLI tool, moved from `scripts/artifact.py` (#37).
- `BeaconConfig.public_key` property (#22).
- `netbios_encode` and `netbios_decode` helper functions in `utils.py` (#23).
- PE export stamps for Cobalt Strike 4.7 and 4.7.1 (#24).
- Message shown for trial beacons (#38).
- Tests for `dissect.cobaltstrike.client` (#35).
- Specific error message for the `flow.record` ImportError (#31).
- Improved documentation and tutorials (#30, #39).

### Fixed

- `--arch` and `--barch` arguments not being parsed (#32).
- Ignore `COMMAND_NOOP` packets (#34).

## [0.2.2] - 2022-09-14

### Added

- Cobalt Strike 4.7 settings and version info (#19).
- `task_*` c2profile settings introduced in Cobalt Strike 4.6 (#20).
- `pe_export_stamp` for the Cobalt Strike 4.6 DNS Beacon (#16).
- `retain_file_offset` helper in `utils.py` (#21).

### Fixed

- Missing DNS beacon settings in c2profile output (#17, #18).

## [0.2.1] - 2022-06-16

### Added

- `u64`, `p64`, `u64be` and `p64be` packing aliases (#15).
- PE export timestamps for Cobalt Strike 4.6.

## [0.2.0] - 2022-04-11

### Added

- Support for reading from stdin in `beacon-dump` (#4).
- Process exit code for `beacon-dump` (#9).

### Fixed

- Handling for empty or all-zero xorkey buffer in `utils.xor` (#5).
- Exception handling in the `@catch_sigpipe` decorator (#2, #7).

## [0.1.0] - 2022-03-25

### Added

- Initial public release of `dissect.cobaltstrike`.

[Unreleased]: https://github.com/fox-it/dissect.cobaltstrike/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/fox-it/dissect.cobaltstrike/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/fox-it/dissect.cobaltstrike/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/fox-it/dissect.cobaltstrike/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fox-it/dissect.cobaltstrike/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fox-it/dissect.cobaltstrike/compare/v0.2.2...v1.0.0
[0.2.2]: https://github.com/fox-it/dissect.cobaltstrike/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/fox-it/dissect.cobaltstrike/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/fox-it/dissect.cobaltstrike/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fox-it/dissect.cobaltstrike/releases/tag/v0.1.0

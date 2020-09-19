# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2020-09-19
### Fixed
- Fixed compatibility with MbedOS 6.3.

## [0.1.0] - 2020-07-03
### Added

- Update "littlefs" code and add `enable_commit_compact_threshold` option that triggers
  directory logs rebuilding to merge log commits. It reduces efficiency of storage usage,
  but increases performance with large blocks.
- Add littlefs wrapper with fixed memory consumption for mbed-os.

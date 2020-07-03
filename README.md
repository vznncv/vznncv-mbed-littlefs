# vznncv-mbed-littlefs

Alternative [littlefs](https://github.com/ARMmbed/littlefs) wrapper for [mbed-os](https://github.com/ARMmbed/mbed-os).

## Motivation

The base littlefs wrappers for mbed-os use dynamic memory allocation, that is usually unwanted for embedded systems.
To solve this problem this library has been created. It uses internally memory pools to allocate 
helper file structures and buffers. But it limits maximal number of concurrently opened files/directories and
causes memory usage even no files/directories are opened.

Additionally it contains patches to improve littlefs performance with large block devices like SD card.
The LittleFS has some problems with block allocator: https://github.com/ARMmbed/littlefs/issues/75
that cause some problem with large storage. To fix it, the block size may be increased, but it
causes another issues - slow directory operations due growing of directory logs. To fix it, the
`enable_commit_compact_threshold` option and `commit_compact_threshold` parameter is added. They
trigger directory compact operation before a directory block becomes full. It increases storage wearing,
but prevents directory logs grown and improves performance.

## LittleFS source files

LittleFS source files with patches are stored in the `littlefs_src` directory.
This directory contains the following subfolders and files:

- `littelfs_original` - original littlefs source files. This folder is ignored by git and mbed build system.
- `littlefs_prefix` - littlefs source files with extra prefix. Prefixes are added to source files and function/struct names.
                      The prefixes are added to avoid name conflicts with source files from `mbed-os`. This folder is ignored
                      by git and mbed build system too.
- `littlefs_patched` - littelfs source files with prefixes and patches. These source files are used in a project.
- `littlefs_patches` - patch files that are applied to `littlefs_prefix` to create `littlefs_patched`.
- `manage.sh` - helper script to update littlefs source files and patches.

Base source file modification workflow:

1. Run `manage.sh generate-sources`. This command downloads littlefs sources, adds prefixes and applies patches to
   create/update `littlefs_patched` folder.
2. Update littlefs files in the `littlefs_patched` folder.
3. Run `manage.sh generate-patches` to update patches in the `littlefs_patches`.
4. Commit changes.

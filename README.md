# vznncv-mbed-littlefs

Alternative [littlefs](https://github.com/ARMmbed/littlefs) wrapper for [mbed-os](https://github.com/ARMmbed/mbed-os).

## Motivation

The base littlefs wrappers for mbed-os use dynamic memory allocation, that is usually unwanted for embedded systems.
To solve this problem this library has been created. It uses internally memory pools to allocate 
helper file structures and buffers. But it limits maximal number of concurrently opened files/directories and
causes memory usage even no files/directories are opened.
Additionally it contains some patches for littlefs that improves performance with large block devices like SD cards.

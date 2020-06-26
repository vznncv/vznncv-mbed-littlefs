#include "vznncv_mbed_lfs_config.h"

#include "mbed.h"

extern "C" uint32_t vznncv_lfs_crc(uint32_t crc, const void *buffer, size_t size)
{
    uint32_t initial_xor = vznncv_lfs_rbit(crc);
    MbedCRC<POLY_32BIT_ANSI, 32, CrcMode::TABLE> ct(initial_xor, 0x0, true, true);

    ct.compute((void *)buffer, size, &crc);
    return crc;
}

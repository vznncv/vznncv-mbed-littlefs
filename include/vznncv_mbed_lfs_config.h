#ifndef VZNNCV_MBED_LFS_CONFIG_H
#define VZNNCV_MBED_LFS_CONFIG_H

// system includes
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if MBED_CONF_VZNNCV_MBED_LITTELFS_USE_MBED_TRACE
#include "mbed_trace.h"
#define TRACE_GROUP "vzlf"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "cmsis_compiler.h"
#include "mbed_assert.h"

// Macros, may be replaced by system specific wrappers. Arguments to these
// macros must not have side-effects as the macros can be removed for a smaller
// code footprint

// resolve "null" configuration values
#ifndef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_TRACE
#ifdef MBED_DEBUG
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_TRACE true
#else
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_TRACE false
#endif
#endif

#ifndef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_WARN
#ifdef MBED_DEBUG
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_WARN true
#else
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_WARN false
#endif
#endif

#ifndef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ERROR
#ifdef MBED_DEBUG
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ERROR true
#else
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ERROR false
#endif
#endif

#ifndef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_DEBUG
#ifdef MBED_DEBUG
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_DEBUG true
#else
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_DEBUG false
#endif
#endif

#ifndef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ASSERT
#ifdef MBED_DEBUG
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ASSERT true
#else
#define MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ASSERT false
#endif
#endif

// logger functions
#if MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_TRACE
#if MBED_CONF_VZNNCV_MBED_LITTELFS_USE_MBED_TRACE
#define VZNNCV_LFS_TRACE(...) tr_info(__VA_ARGS__)
#else
#define VZNNCV_LFS_TRACE(fmt, ...) fprintf(stderr, "%s:%d:trace: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__)
#endif
#else
#define VZNNCV_LFS_TRACE(...)
#endif

#if MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_DEBUG
#if MBED_CONF_VZNNCV_MBED_LITTELFS_USE_MBED_TRACE
#define VZNNCV_LFS_DEBUG(...) tr_debug(__VA_ARGS__)
#else
#define VZNNCV_LFS_DEBUG(fmt, ...) fprintf(stderr, "%s:%d:debug: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__)
#endif
#else
#define VZNNCV_LFS_DEBUG(...)
#endif

#if MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_WARN
#if MBED_CONF_VZNNCV_MBED_LITTELFS_USE_MBED_TRACE
#define VZNNCV_LFS_WARN(...) tr_warn(__VA_ARGS__)
#else
#define VZNNCV_LFS_WARN(fmt, ...) fprintf(stderr, "%s:%d:warn: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__)
#endif
#else
#define VZNNCV_LFS_WARN(...)
#endif

#if MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ERROR
#if MBED_CONF_VZNNCV_MBED_LITTELFS_USE_MBED_TRACE
#define VZNNCV_LFS_ERROR(...) tr_error(__VA_ARGS__)
#else
#define VZNNCV_LFS_ERROR(fmt, ...) fprintf(stderr, "%s:%d:error: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__)
#endif
#else
#define VZNNCV_LFS_ERROR(...)
#endif

// Runtime assertions
#if MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_ASSERT
#define VZNNCV_LFS_ASSERT(test) MBED_ASSERT(test)
#else
#define VZNNCV_LFS_ASSERT(test)
#endif

// Builtin functions, these may be replaced by more efficient
// toolchain-specific implementations. VZNNCV_LFS_NO_INTRINSICS falls back to a more
// expensive basic C implementation for debugging purposes

// Min/max functions for unsigned 32-bit numbers
static inline uint32_t vznncv_lfs_max(uint32_t a, uint32_t b)
{
    return (a > b) ? a : b;
}

static inline uint32_t vznncv_lfs_min(uint32_t a, uint32_t b)
{
    return (a < b) ? a : b;
}

// Align to nearest multiple of a size
static inline uint32_t vznncv_lfs_aligndown(uint32_t a, uint32_t alignment)
{
    return a - (a % alignment);
}

static inline uint32_t vznncv_lfs_alignup(uint32_t a, uint32_t alignment)
{
    return vznncv_lfs_aligndown(a + alignment - 1, alignment);
}

// Find the smallest power of 2 greater than or equal to a
static inline uint32_t vznncv_lfs_npw2(uint32_t a)
{
#if MBED_CONF_VZNNCV_MBED_LITTELFS_INTRINSICS && (defined(__GNUC__) || defined(__CC_ARM))
    return 32 - __builtin_clz(a - 1);
#else
    uint32_t r = 0;
    uint32_t s;
    a -= 1;
    s = (a > 0xffff) << 4;
    a >>= s;
    r |= s;
    s = (a > 0xff) << 3;
    a >>= s;
    r |= s;
    s = (a > 0xf) << 2;
    a >>= s;
    r |= s;
    s = (a > 0x3) << 1;
    a >>= s;
    r |= s;
    return (r | (a >> 1)) + 1;
#endif
}

// Count the number of trailing binary zeros in a
// vznncv_lfs_ctz(0) may be undefined
static inline uint32_t vznncv_lfs_ctz(uint32_t a)
{
#if MBED_CONF_VZNNCV_MBED_LITTELFS_INTRINSICS && defined(__GNUC__)
    return __builtin_ctz(a);
#else
    return vznncv_lfs_npw2((a & -a) + 1) - 1;
#endif
}

// Count the number of binary ones in a
static inline uint32_t vznncv_lfs_popc(uint32_t a)
{
#if MBED_CONF_VZNNCV_MBED_LITTELFS_INTRINSICS && (defined(__GNUC__) || defined(__CC_ARM))
    return __builtin_popcount(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
#endif
}

// Find the sequence comparison of a and b, this is the distance
// between a and b ignoring overflow
static inline int vznncv_lfs_scmp(uint32_t a, uint32_t b)
{
    return (int)(unsigned)(a - b);
}

// Convert between 32-bit little-endian and native order
static inline uint32_t vznncv_lfs_fromle32(uint32_t a)
{
#if MBED_CONF_VZNNCV_MBED_LITTELFS_INTRINSICS && ((defined(BYTE_ORDER) && defined(ORDER_LITTLE_ENDIAN) && BYTE_ORDER == ORDER_LITTLE_ENDIAN) || (defined(__BYTE_ORDER) && defined(__ORDER_LITTLE_ENDIAN) && __BYTE_ORDER == __ORDER_LITTLE_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return a;
#elif !defined(VZNNCV_LFS_NO_INTRINSICS) && ((defined(BYTE_ORDER) && defined(ORDER_BIG_ENDIAN) && BYTE_ORDER == ORDER_BIG_ENDIAN) || (defined(__BYTE_ORDER) && defined(__ORDER_BIG_ENDIAN) && __BYTE_ORDER == __ORDER_BIG_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
    return __builtin_bswap32(a);
#else
    return (((uint8_t *)&a)[0] << 0) | (((uint8_t *)&a)[1] << 8) | (((uint8_t *)&a)[2] << 16) | (((uint8_t *)&a)[3] << 24);
#endif
}

static inline uint32_t vznncv_lfs_tole32(uint32_t a)
{
    return vznncv_lfs_fromle32(a);
}

// Convert between 32-bit big-endian and native order
static inline uint32_t vznncv_lfs_frombe32(uint32_t a)
{
#if MBED_CONF_VZNNCV_MBED_LITTELFS_INTRINSICS && ((defined(BYTE_ORDER) && defined(ORDER_LITTLE_ENDIAN) && BYTE_ORDER == ORDER_LITTLE_ENDIAN) || (defined(__BYTE_ORDER) && defined(__ORDER_LITTLE_ENDIAN) && __BYTE_ORDER == __ORDER_LITTLE_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return __builtin_bswap32(a);
#elif MBED_CONF_VZNNCV_MBED_LITTELFS_INTRINSICS && ((defined(BYTE_ORDER) && defined(ORDER_BIG_ENDIAN) && BYTE_ORDER == ORDER_BIG_ENDIAN) || (defined(__BYTE_ORDER) && defined(__ORDER_BIG_ENDIAN) && __BYTE_ORDER == __ORDER_BIG_ENDIAN) || (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
    return a;
#else
    return (((uint8_t *)&a)[0] << 24) | (((uint8_t *)&a)[1] << 16) | (((uint8_t *)&a)[2] << 8) | (((uint8_t *)&a)[3] << 0);
#endif
}

static inline uint32_t vznncv_lfs_tobe32(uint32_t a)
{
    return vznncv_lfs_frombe32(a);
}

// Reverse the bits in a
static inline uint32_t vznncv_lfs_rbit(uint32_t a)
{
#if MBED_CONF_VZNNCV_MBED_LITTELFS_INTRINSICS && defined(__MBED__)
    return __RBIT(a);
#else
    a = ((a & 0xaaaaaaaa) >> 1) | ((a & 0x55555555) << 1);
    a = ((a & 0xcccccccc) >> 2) | ((a & 0x33333333) << 2);
    a = ((a & 0xf0f0f0f0) >> 4) | ((a & 0x0f0f0f0f) << 4);
    a = ((a & 0xff00ff00) >> 8) | ((a & 0x00ff00ff) << 8);
    a = (a >> 16) | (a << 16);
    return a;
#endif
}

// Calculate CRC-32 with polynomial = 0x04c11db7
uint32_t vznncv_lfs_crc(uint32_t crc, const void *buffer, size_t size);

// Allocate memory, only used if buffers are not provided to littlefs
// Note, memory must be 64-bit aligned
static inline void *vznncv_lfs_malloc(size_t size)
{
    return malloc(size);
}

// Deallocate memory, only used if buffers are not provided to littlefs
static inline void vznncv_lfs_free(void *p)
{
    free(p);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // VZNNCV_MBED_LFS_CONFIG_H

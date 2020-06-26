#ifndef VZNNCV_MBED_LFS_SIMPLE_MEMORY_POOL_H
#define VZNNCV_MBED_LFS_SIMPLE_MEMORY_POOL_H

#include <stdint.h>
#include <stdlib.h>

#include "mbed.h"

namespace vznncv {

/**
 * Simple memory pool with dynamic memory allocation.
 *
 * Unlike mbed::MemoryPool it isn't a template and accepts memory block size and number of blocks as a constructor arguments.
 *
 * note: this implementation isn't a thread safe.
 */
template <class T>
class SimpleMemoryPool {
private:
    const uint16_t _block_size;
    const uint8_t _block_num;
    const uint8_t _usage_map_size;

    // pool memory structure:
    // | block_usage_mask | block_0 | block_1 | ... | block_<n-1> |
    uint8_t *_data;

    SimpleMemoryPool(const SimpleMemoryPool &) = delete;
    SimpleMemoryPool &operator=(const SimpleMemoryPool &) = delete;

protected:
    SimpleMemoryPool(size_t block_size, size_t block_num);

    static size_t _round_up(size_t value, size_t precision)
    {
        size_t remainder = value % precision;
        if (remainder) {
            value += (precision - remainder);
        }
        return value;
    }

    static size_t _align_size_up(size_t value)
    {
        // get alignment value
        // TODO: check correctness
        return _round_up(value, alignof(std::max_align_t));
    }

public:
    /**
     * SimpleMemoryPool
     *
     * note: to reduce memory usage, current implementation has the following restrictions
     * - @p block_size should be less or equal to 0xFFFF
     * - @p block_num should be less or equal to 0x0800
     *
     * @param block_num number of blocks
     */
    SimpleMemoryPool(size_t block_num);
    ~SimpleMemoryPool();

    /**
     * Allocate block.
     *
     * @return allocated memory block or `NULL` if there is no more space.
     */
    T *allocate();

    /**
     * Return allocated memory block to pool.
     *
     * @param ptr memory block. It should be a pointer that is returned by the ::allocate method.
     */
    void deallocate(T *ptr);

    /**
     * Get total pool size.
     *
     * @return
     */
    size_t size()
    {
        return _block_num;
    }

    /**
     * Apply callback to all memory blocks inside pool.
     *
     * This method can be used for data initialization/deinitialization.;
     *
     * @param block_cb callback that accepts point to block and usage flag
     * @return
     */
    int process_blocks(Callback<int(T *, bool)> block_cb);
};

template <class T>
SimpleMemoryPool<T>::SimpleMemoryPool(size_t block_size, size_t block_num)
    : _block_size(_align_size_up(block_size))
    , _block_num(block_num)
    , _usage_map_size(_align_size_up(block_num / 8 + (block_num % 8 == 0 ? 0 : 1)))
    , _data(nullptr)
{
    MBED_ASSERT(block_num <= 0x0800);
    MBED_ASSERT(block_size <= 0xFFFF);
    // allocate data
    _data = (uint8_t *)malloc(_block_size * _block_num + _usage_map_size);
    // clear usage map
    memset(_data, 0, _usage_map_size);
}

template <class T>
SimpleMemoryPool<T>::SimpleMemoryPool(size_t block_num)
    : SimpleMemoryPool(sizeof(T), block_num)
{
}

template <class T>
SimpleMemoryPool<T>::~SimpleMemoryPool()
{
    ::free(_data);
}

template <class T>
T *SimpleMemoryPool<T>::allocate()
{
    int block_no = 0;
    T *block;

    // find free block
    for (size_t i = 0; i < _usage_map_size; i++) {
        uint8_t usage_map_elem = _data[i];
        if (usage_map_elem != 0xFF) {
            while (usage_map_elem & 0x01) {
                usage_map_elem >>= 1;
                block_no++;
            }
            break;
        }
        block_no += 8;
    }

    if (block_no >= _block_num) {
        // no free blocks are found
        block = nullptr;
    } else {
        // allocate block
        block = (T *)(_data + _usage_map_size + block_no * _block_size);
        _data[block_no / 8] |= 0x01 << (block_no % 8);
    }

    return block;
}

template <class T>
void SimpleMemoryPool<T>::deallocate(T *ptr)
{
    // check and resolve block number
    int offset = ((uint8_t *)ptr - _data) - _usage_map_size;
    int block_no = offset / _block_size;
    if (offset % _block_size != 0 || block_no < 0 || block_no >= _block_num) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_EINVAL), "invalid pointer inside SimpleMemoryPool::deallocate");
    }
    // mark block as "free"
    uint8_t mask = 0x01 << (block_no % 8);
    _data[block_no / 8] &= ~mask;
}

template <class T>
int SimpleMemoryPool<T>::process_blocks(Callback<int(T *, bool)> block_cb)
{
    int err = 0;
    int cb_err;
    bool usage_flag;
    T *block;

    for (size_t i = 0; i < _block_num; i++) {
        usage_flag = _data[i / 8] & (0x01 << (i % 8));
        block = (T *)(_data + _usage_map_size + _block_size * i);
        cb_err = block_cb(block, usage_flag);
        if (cb_err && !err) {
            err = cb_err;
        }
    }

    return err;
}
}

#endif // VZNNCV_MBED_LFS_SIMPLE_MEMORY_POOL_H

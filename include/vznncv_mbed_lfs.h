#ifndef VZNNCV_MBED_LFS_H
#define VZNNCV_MBED_LFS_H

#include "BlockDevice.h"
#include "FileSystem.h"
#include "PlatformMutex.h"
#include "vznncv_lfs.h"

#include "vznncv_mbed_lfs_simple_memory_pool.h"

namespace vznncv {

/**
 * Alternative LittleFS wrapper with fixed memory consumption.
 *
 * Notes:
 * 1. the code is based on a "LittleFileSystem2.h"
 * 2. to eliminate dynamic memory allocation use a system function open/write/read/close to work with files
 *    instead of fopen, fwrite, fread and fclose, as internally c library can allocate memory.
 *
 * Synchronization level: Thread safe
 */
class FMLittleFileSystem2 : public mbed::FileSystem {
protected:
    // thread-safe locking
    PlatformMutex _mutex;

    // note: vznncv_lfs_info structure is large, so put it here to prevent stack overflow
    struct vznncv_lfs_info _lfs_info = { 0 };

    // default parameters
    const vznncv_lfs_size_t _default_block_size;
    const uint32_t _default_block_cycles;
    const vznncv_lfs_size_t _default_cache_size;
    const vznncv_lfs_size_t _default_lookahead_size;

    const vznncv_lfs_size_t _commit_compact_threshold;

    // maximal number of opened files/directories
    const size_t _max_file_num = 0;
    const size_t _max_dir_num = 0;

    // file system structures
    vznncv_lfs_t _lfs;
    struct vznncv_lfs_config _config = {};
    // block devices
    BlockDevice *_bd = nullptr;

    //
    // Helper classes and structs to keep preallocated memory
    //
    struct file_entity_t;
    struct dir_entity_t;
    using FileEntityPool = SimpleMemoryPool<file_entity_t>;
    using DirEntityPool = SimpleMemoryPool<dir_entity_t>;

    //
    // Helper classes to release allocated memory
    //
    class FileHandlerImpl : public File {
    private:
        FileEntityPool *_pool;
        file_entity_t *_file_entity;

    public:
        FileHandlerImpl(FileEntityPool *pool, file_entity_t *file_entity)
            : _pool(pool)
            , _file_entity(file_entity)
        {
        }
        int close() override;

        ~FileHandlerImpl() override = default;
    };

    class DirHandlerImpl : public Dir {
    private:
        DirEntityPool *_pool;
        dir_entity_t *_dir_entity;

    public:
        DirHandlerImpl(DirEntityPool *pool, dir_entity_t *dir_entity)
            : _pool(pool)
            , _dir_entity(dir_entity)
        {
        }
        int close() override;

        ~DirHandlerImpl() override = default;
    };

    // helper struct for file memory preallocation
    struct file_entity_t {
        alignas(FileHandlerImpl) uint8_t file_handle[sizeof(FileHandlerImpl)];
        vznncv_lfs_file_t lfs_file;
        struct vznncv_lfs_file_config lfs_file_cfg;
        void *buffer;
    };
    // helper struct for directory memory preallocation
    struct dir_entity_t {
        alignas(DirHandlerImpl) uint8_t dir_handle[sizeof(DirHandlerImpl)];
        vznncv_lfs_dir_t lfs_dir;
    };

    //
    // Pools and function to keep preallocated memory
    //

    // Allocate/reallocate internal memory.
    int _prepare_memory(size_t max_files, size_t max_dirs, size_t prog_buf_size);
    // Cleanup internal memory.
    int _clear_memory();
    struct file_buffer_manager_t {
        size_t old_size;
        size_t new_size;
        int process_file_buffer(file_entity_t *obj, bool usage_flag);
    };
    // Helper pointers for "open/close" methods.
    // If they are NULL, then open/close methods allocate/deallocate  memory itself,
    // otherwise they use this pointers and outer code should do it.
    file_entity_t *_active_file_entity = nullptr;
    dir_entity_t *_active_dir_entity = nullptr;
    // memory pools
    FileEntityPool *_file_entity_pool = nullptr;
    DirEntityPool *_dir_entity_pool = nullptr;
    size_t _prog_buf_size = 0;

    // helper methods to covert operational codes
    static int _lfs_to_error(int err);
    static int _lfs_from_flags(int flags);
    static int _lfs_from_whence(int whence);
    static int _lfs_to_mode(int type);
    static int _lfs_to_type(int type);
    // block device API
    static int _lfs_bd_read(const struct vznncv_lfs_config *c, vznncv_lfs_block_t block, vznncv_lfs_off_t off, void *buffer, vznncv_lfs_size_t size);
    static int _lfs_bd_prog(const struct vznncv_lfs_config *c, vznncv_lfs_block_t block, vznncv_lfs_off_t off, const void *buffer, vznncv_lfs_size_t size);
    static int _lfs_bd_erase(const struct vznncv_lfs_config *c, vznncv_lfs_block_t block);
    static int _lfs_bd_sync(const struct vznncv_lfs_config *c);

public:
    /**
     *  Constructor.
     *
     *  @param name Name of the file system in the tree.
     *  @param max_file_num maximal number of concurrently opened files.
     *  @param max_dir_num maximal number of concurrently opened directories.
     *  @param block_size size of a logical block
     *  @param block_cycles number of erase cycles before a block is forcefully evicted
     *  @param cache_size size of read/program caches
     *  @param lookahead_size size of the lookahead buffer
     *  @param commit_compact_threshold maximal directory commit number after that compact operations will be triggered forcibly.
     *         To use this option the "vznncv-mbed-littelfs.enable_commit_compact_threshold" option should be enabled.
     */
    FMLittleFileSystem2(const char *name = NULL,
        size_t max_file_num = 1,
        size_t max_dir_num = 1,
        vznncv_lfs_size_t block_size = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_BLOCK_SIZE,
        uint32_t block_cycles = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_BLOCK_CYCLES,
        vznncv_lfs_size_t cache_size = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_CACHE_SIZE,
        vznncv_lfs_size_t lookahead = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_LOOKAHEAD_SIZE,
        vznncv_lfs_size_t commit_compact_threshold = 0);

    virtual ~FMLittleFileSystem2();

private:
    /**
     * Format a block device with the littlefs 2.
     *
     * The block device to format should be mounted when this function is called.
     *
     * Note: implementation can allocate memory during device formating.
     *
     *  @param bd       This is the block device that will be formatted.
     *  @param block_size
     *      Size of a logical block. This does not impact ram consumption and
     *      may be larger than the physical erase block. If the physical erase
     *      block is larger, littlefs will use that instead. Larger values will
     *      be faster but waste more storage when files are not aligned to a
     *      block size.
     *  @param block_cycles
     *      Number of erase cycles before a block is forcefully evicted. Larger
     *      values are more efficient but cause less even wear distribution. 0
     *      disables dynamic wear-leveling.
     *  @param cache_size
     *      Size of read/program caches. Each file uses 1 cache, and littlefs
     *      allocates 2 caches for internal operations. Larger values should be
     *      faster but uses more RAM.
     *  @param lookahead_size
     *      Size of the lookahead buffer. A larger lookahead reduces the
     *      allocation scans and results in a faster filesystem but uses
     *      more RAM.
     */
    int _format_impl(BlockDevice *bd,
        vznncv_lfs_size_t block_size = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_BLOCK_SIZE,
        uint32_t block_cycles = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_BLOCK_CYCLES,
        vznncv_lfs_size_t cache_size = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_CACHE_SIZE,
        vznncv_lfs_size_t lookahead_size = MBED_CONF_VZNNCV_MBED_LITTELFS_DEFAULT_LOOKAHEAD_SIZE);

    static int _init_lfs_config(
        BlockDevice *bd, struct vznncv_lfs_config *config,
        vznncv_lfs_size_t block_size,
        uint32_t block_cycles,
        vznncv_lfs_size_t cache_size,
        vznncv_lfs_size_t lookahead_size,
        vznncv_lfs_size_t commit_compact_threshold);

    //
    // FileSystem methods implementation
    //
public:
    virtual int mount(mbed::BlockDevice *bd) override;
    virtual int unmount() override;
    virtual int reformat(mbed::BlockDevice *bd) override;

    virtual int remove(const char *path) override;
    virtual int rename(const char *path, const char *newpath) override;
    virtual int stat(const char *path, struct stat *st) override;
    virtual int mkdir(const char *path, mode_t mode) override;
    virtual int statvfs(const char *path, struct statvfs *buf) override;

protected:
    virtual int file_open(mbed::fs_file_t *file, const char *path, int flags) override;
    virtual int file_close(mbed::fs_file_t file) override;
    virtual ssize_t file_read(mbed::fs_file_t file, void *buffer, size_t size) override;
    virtual ssize_t file_write(mbed::fs_file_t file, const void *buffer, size_t size) override;
    virtual int file_sync(mbed::fs_file_t file) override;
    virtual off_t file_seek(mbed::fs_file_t file, off_t offset, int whence) override;
    virtual off_t file_tell(mbed::fs_file_t file) override;
    virtual off_t file_size(mbed::fs_file_t file) override;
    virtual int file_truncate(mbed::fs_file_t file, off_t length) override;

    virtual int dir_open(mbed::fs_dir_t *dir, const char *path) override;
    virtual int dir_close(mbed::fs_dir_t dir) override;
    virtual ssize_t dir_read(mbed::fs_dir_t dir, struct dirent *ent) override;
    virtual void dir_seek(mbed::fs_dir_t dir, off_t offset) override;
    virtual off_t dir_tell(mbed::fs_dir_t dir) override;
    virtual void dir_rewind(mbed::fs_dir_t dir) override;

protected:
    // Hooks for file systemHandle
    virtual int open(mbed::FileHandle **file, const char *path, int flags) override;
    virtual int open(mbed::DirHandle **dir, const char *path) override;
};
}

#endif // VZNNCV_MBED_LFS_H

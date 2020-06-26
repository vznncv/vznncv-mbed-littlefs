#include <mutex>

using std::lock_guard;

#include "vznncv_lfs_util.h"
#include "vznncv_mbed_lfs.h"
#include "vznncv_mbed_lfs_config.h"

namespace vznncv {

typedef lock_guard<PlatformMutex> mbed_lock_guard;

FMLittleFileSystem2::FMLittleFileSystem2(const char *name, size_t max_file_num, size_t max_dir_num, vznncv_lfs_size_t block_size, uint32_t block_cycles, vznncv_lfs_size_t cache_size, vznncv_lfs_size_t lookahead)
    : FileSystem(name)

    , _default_block_size(block_size)
    , _default_block_cycles(block_cycles)
    , _default_cache_size(cache_size)
    , _default_lookahead_size(lookahead)
    , _max_file_num(max_file_num)
    , _max_dir_num(max_dir_num)

    , _active_file_entity(nullptr)
    , _active_dir_entity(nullptr)

    , _file_entity_pool(nullptr)
    , _dir_entity_pool(nullptr)
    , _prog_buf_size(0)
{
}

FMLittleFileSystem2::~FMLittleFileSystem2()
{
    unmount();
    int err = _clear_memory();
    if (err) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_CODE_CLOSE_FAILED), "Fail cleanup allocated memory");
    }
}

int FMLittleFileSystem2::file_buffer_manager_t::process_file_buffer(FMLittleFileSystem2::file_entity_t *obj, bool usage_flag)
{
    if (old_size == 0) {
        if (new_size != 0) {
            obj->buffer = new uint8_t[new_size];
        }
    } else {
        if (new_size == 0) {
            delete[](uint8_t *)(obj->buffer);
        } else {
            // reallocate buffer
            delete[](uint8_t *)(obj->buffer);
            obj->buffer = new uint8_t[new_size];
        }
    }

    return usage_flag ? -1 : 0;
}

int FMLittleFileSystem2::_prepare_memory(size_t max_files, size_t max_dirs, size_t prog_buf_size)
{
    mbed_lock_guard lck(_mutex);
    int err = 0;
    int op_err = 0;

    // update file pool
    file_buffer_manager_t file_buffer_manager;
    if (_file_entity_pool != nullptr && _file_entity_pool->size() != max_files) {
        file_buffer_manager.old_size = _prog_buf_size;
        file_buffer_manager.new_size = 0;
        op_err = _file_entity_pool->process_blocks(callback(&file_buffer_manager, &file_buffer_manager_t::process_file_buffer));
        if (op_err) {
            err = op_err;
        }
        delete _file_entity_pool;
        _file_entity_pool = nullptr;
        _prog_buf_size = 0;
    }
    if (_file_entity_pool == nullptr && max_files != 0) {
        _file_entity_pool = new FileEntityPool(max_files);
    }
    if (_file_entity_pool != nullptr && _prog_buf_size != prog_buf_size) {
        file_buffer_manager.old_size = _prog_buf_size;
        file_buffer_manager.new_size = prog_buf_size;
        op_err = _file_entity_pool->process_blocks(callback(&file_buffer_manager, &file_buffer_manager_t::process_file_buffer));
        if (op_err) {
            err = op_err;
        }
        _prog_buf_size = prog_buf_size;
    }

    // update directory pool
    if (_dir_entity_pool != nullptr && _dir_entity_pool->size() != max_dirs) {
        delete _dir_entity_pool;
        _dir_entity_pool = nullptr;
    }
    if (_dir_entity_pool == nullptr && max_dirs != 0) {
        _dir_entity_pool = new DirEntityPool(max_dirs);
    }

    return err;
}

int FMLittleFileSystem2::_clear_memory()
{
    mbed_lock_guard lck(_mutex);
    return _prepare_memory(0, 0, 0);
}

//
// Conversion functions
//

int FMLittleFileSystem2::_lfs_to_error(int err)
{
    switch (err) {
    case VZNNCV_LFS_ERR_OK:
        return 0;
    case VZNNCV_LFS_ERR_IO:
        return -EIO;
    case VZNNCV_LFS_ERR_NOENT:
        return -ENOENT;
    case VZNNCV_LFS_ERR_EXIST:
        return -EEXIST;
    case VZNNCV_LFS_ERR_NOTDIR:
        return -ENOTDIR;
    case VZNNCV_LFS_ERR_ISDIR:
        return -EISDIR;
    case VZNNCV_LFS_ERR_INVAL:
        return -EINVAL;
    case VZNNCV_LFS_ERR_NOSPC:
        return -ENOSPC;
    case VZNNCV_LFS_ERR_NOMEM:
        return -ENOMEM;
    case VZNNCV_LFS_ERR_CORRUPT:
        return -EILSEQ;
    default:
        return err;
    }
}

int FMLittleFileSystem2::_lfs_from_flags(int flags)
{
    return (
        (((flags & 3) == O_RDONLY) ? VZNNCV_LFS_O_RDONLY : 0) | (((flags & 3) == O_WRONLY) ? VZNNCV_LFS_O_WRONLY : 0) | (((flags & 3) == O_RDWR) ? VZNNCV_LFS_O_RDWR : 0) | ((flags & O_CREAT) ? VZNNCV_LFS_O_CREAT : 0) | ((flags & O_EXCL) ? VZNNCV_LFS_O_EXCL : 0) | ((flags & O_TRUNC) ? VZNNCV_LFS_O_TRUNC : 0) | ((flags & O_APPEND) ? VZNNCV_LFS_O_APPEND : 0));
}

int FMLittleFileSystem2::_lfs_from_whence(int whence)
{
    switch (whence) {
    case SEEK_SET:
        return VZNNCV_LFS_SEEK_SET;
    case SEEK_CUR:
        return VZNNCV_LFS_SEEK_CUR;
    case SEEK_END:
        return VZNNCV_LFS_SEEK_END;
    default:
        return whence;
    }
}

int FMLittleFileSystem2::_lfs_to_mode(int type)
{
    int mode = S_IRWXU | S_IRWXG | S_IRWXO;
    switch (type) {
    case VZNNCV_LFS_TYPE_DIR:
        return mode | S_IFDIR;
    case VZNNCV_LFS_TYPE_REG:
        return mode | S_IFREG;
    default:
        return 0;
    }
}

static int vznncv_lfs_totype(int type)
{
    switch (type) {
    case VZNNCV_LFS_TYPE_DIR:
        return DT_DIR;
    case VZNNCV_LFS_TYPE_REG:
        return DT_REG;
    default:
        return DT_UNKNOWN;
    }
}

//
// Block device operations
//

int FMLittleFileSystem2::_lfs_bd_read(const struct vznncv_lfs_config *c, vznncv_lfs_block_t block,
    vznncv_lfs_off_t off, void *buffer, vznncv_lfs_size_t size)
{
    BlockDevice *bd = (BlockDevice *)c->context;
    int err = bd->read(buffer, (bd_addr_t)block * c->block_size + off, size);
    if (err) {
        VZNNCV_LFS_ERROR("read error");
    }
    return err;
}

int FMLittleFileSystem2::_lfs_bd_prog(const struct vznncv_lfs_config *c, vznncv_lfs_block_t block,
    vznncv_lfs_off_t off, const void *buffer, vznncv_lfs_size_t size)
{
    BlockDevice *bd = (BlockDevice *)c->context;
    int err = bd->program(buffer, (bd_addr_t)block * c->block_size + off, size);
    if (err) {
        VZNNCV_LFS_ERROR("program error");
    }
    return err;
}

int FMLittleFileSystem2::_lfs_bd_erase(const struct vznncv_lfs_config *c, vznncv_lfs_block_t block)
{
    BlockDevice *bd = (BlockDevice *)c->context;
    int err = bd->erase((bd_addr_t)block * c->block_size, c->block_size);
    if (err) {
        VZNNCV_LFS_ERROR("erase error");
    }
    return err;
}

int FMLittleFileSystem2::_lfs_bd_sync(const struct vznncv_lfs_config *c)
{
    BlockDevice *bd = (BlockDevice *)c->context;
    int err = bd->sync();
    if (err) {
        VZNNCV_LFS_ERROR("sync error");
    }
    return err;
}

//
// Generic initialization functions
//

int FMLittleFileSystem2::_format_impl(BlockDevice *bd, vznncv_lfs_size_t block_size, uint32_t block_cycles, vznncv_lfs_size_t cache_size, vznncv_lfs_size_t lookahead_size)
{
    int err = bd->init();
    if (err) {
        return err;
    }

    // note: the method is invoked inside "reformat", when current system is unmounted, so we can reuse files "_fs" and "_config"
    _init_lfs_config(bd, &_config, block_size, block_cycles, cache_size, lookahead_size);

    err = vznncv_lfs_format(&_lfs, &_config);
    if (err) {
        return _lfs_to_error(err);
    }

    err = bd->deinit();
    if (err) {
        return err;
    }

    return 0;
}

int FMLittleFileSystem2::_init_lfs_config(
    BlockDevice *bd, vznncv_lfs_config *config,
    vznncv_lfs_size_t block_size,
    uint32_t block_cycles,
    vznncv_lfs_size_t cache_size,
    vznncv_lfs_size_t lookahead_size)
{
    memset(config, 0, sizeof(vznncv_lfs_config));
    config->context = bd;
    config->read = _lfs_bd_read;
    config->prog = _lfs_bd_prog;
    config->erase = _lfs_bd_erase;
    config->sync = _lfs_bd_sync;
    config->read_size = bd->get_read_size();
    config->prog_size = bd->get_program_size();
    config->block_size = vznncv_lfs_max(block_size, (vznncv_lfs_size_t)bd->get_erase_size());
    config->block_count = bd->size() / config->block_size;
    config->block_cycles = block_cycles;
    config->cache_size = vznncv_lfs_max(cache_size, config->prog_size);
    config->lookahead_size = vznncv_lfs_min(lookahead_size, 8 * ((config->block_count + 63) / 64));
    return 0;
}

int FMLittleFileSystem2::mount(BlockDevice *bd)
{
    mbed_lock_guard lck(_mutex);

    if (_bd) {
        return -EBUSY;
    }

    _bd = bd;
    int err = _bd->init();
    if (err) {
        _bd = nullptr;
        return err;
    }

    // mount file system
    // note: vznncv_lfs_mount can cause some memory allocations
    _init_lfs_config(bd, &_config, _default_block_size, _default_block_cycles, _default_cache_size, _default_lookahead_size);
    err = vznncv_lfs_mount(&_lfs, &_config);
    if (err) {
        _bd = nullptr;
        return _lfs_to_error(err);
    }

    // allocate memory for file operations
    err = _prepare_memory(_max_file_num, _max_dir_num, _config.prog_size);
    if (err) {
        _bd = nullptr;
        return -ENOMEM;
    }

    return 0;
}

int FMLittleFileSystem2::unmount()
{
    mbed_lock_guard lck(_mutex);

    int res = 0;
    if (_bd) {
        int err = vznncv_lfs_unmount(&_lfs);
        if (err && !res) {
            res = _lfs_to_error(err);
        }

        err = _bd->deinit();
        if (err && !res) {
            res = err;
        }

        _bd = nullptr;

        // cleanup memory
        err = _clear_memory();
        if (err && !res) {
            res = err;
        }
    }

    return res;
}

int FMLittleFileSystem2::reformat(BlockDevice *bd)
{
    mbed_lock_guard lck(_mutex);

    // resolve block device
    // if block device is monted, then unmount it
    if (_bd) {
        if (!bd) {
            bd = _bd;
        }
        int err = unmount();
        if (err) {
            return err;
        }
    }
    if (!bd) {
        return -ENODEV;
    }

    // format block device
    int err = _format_impl(bd,
        _default_block_size,
        _default_block_cycles,
        _default_cache_size,
        _default_lookahead_size);
    if (err) {
        return err;
    }

    err = mount(bd);
    if (err) {
        return err;
    }

    return 0;
}

//
// Generic file system functions
//

int FMLittleFileSystem2::remove(const char *filename)
{
    mbed_lock_guard lck(_mutex);
    int err = vznncv_lfs_remove(&_lfs, filename);
    return _lfs_to_error(err);
}

int FMLittleFileSystem2::rename(const char *oldname, const char *newname)
{
    mbed_lock_guard lck(_mutex);
    int err = vznncv_lfs_rename(&_lfs, oldname, newname);
    return _lfs_to_error(err);
}

int FMLittleFileSystem2::mkdir(const char *name, mode_t mode)
{
    mbed_lock_guard lck(_mutex);
    int err = vznncv_lfs_mkdir(&_lfs, name);
    return _lfs_to_error(err);
}

int FMLittleFileSystem2::stat(const char *name, struct stat *st)
{
    mbed_lock_guard lck(_mutex);
    int err = vznncv_lfs_stat(&_lfs, name, &_lfs_info);
    st->st_size = _lfs_info.size;
    st->st_mode = _lfs_to_mode(_lfs_info.type);
    return _lfs_to_error(err);
}

int FMLittleFileSystem2::statvfs(const char *name, struct statvfs *st)
{
    mbed_lock_guard lck(_mutex);
    memset(st, 0, sizeof(struct statvfs));

    vznncv_lfs_ssize_t in_use = 0;
    in_use = vznncv_lfs_fs_size(&_lfs);
    if (in_use < 0) {
        return in_use;
    }

    st->f_bsize = _config.block_size;
    st->f_frsize = _config.block_size;
    st->f_blocks = _config.block_count;
    st->f_bfree = _config.block_count - in_use;
    st->f_bavail = _config.block_count - in_use;
    st->f_namemax = VZNNCV_LFS_NAME_MAX;
    return 0;
}

//
// File operations
//
int FMLittleFileSystem2::file_open(fs_file_t *file, const char *path, int flags)
{
    mbed_lock_guard lck(_mutex);

    // allocate memory block
    file_entity_t *file_entity = _active_file_entity;
    if (file_entity == nullptr) {
        file_entity = _file_entity_pool->allocate();
        if (file_entity == nullptr) {
            return -EMFILE;
        }
    }

    // prepare configuration
    memset(&file_entity->lfs_file_cfg, 0, sizeof(vznncv_lfs_file_config));
    file_entity->lfs_file_cfg.buffer = file_entity->buffer;
    // open file
    int err = vznncv_lfs_file_opencfg(&_lfs, &file_entity->lfs_file, path, _lfs_from_flags(flags), &file_entity->lfs_file_cfg);
    if (!err) {
        *file = file_entity;
    } else if (_active_file_entity == nullptr) {
        _file_entity_pool->deallocate(file_entity);
    }
    return _lfs_to_error(err);
}

int FMLittleFileSystem2::file_close(fs_file_t file)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    int err = vznncv_lfs_file_close(&_lfs, &file_entity->lfs_file);

    // deallocate memory block
    if (_active_file_entity == nullptr) {
        _file_entity_pool->deallocate(file_entity);
    }

    return _lfs_to_error(err);
}

ssize_t FMLittleFileSystem2::file_read(fs_file_t file, void *buffer, size_t len)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    vznncv_lfs_ssize_t res = vznncv_lfs_file_read(&_lfs, &file_entity->lfs_file, buffer, len);
    return _lfs_to_error(res);
}

ssize_t FMLittleFileSystem2::file_write(fs_file_t file, const void *buffer, size_t len)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    vznncv_lfs_ssize_t res = vznncv_lfs_file_write(&_lfs, &file_entity->lfs_file, buffer, len);
    return _lfs_to_error(res);
}

int FMLittleFileSystem2::file_sync(fs_file_t file)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    int err = vznncv_lfs_file_sync(&_lfs, &file_entity->lfs_file);
    return _lfs_to_error(err);
}

off_t FMLittleFileSystem2::file_seek(fs_file_t file, off_t offset, int whence)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    off_t res = vznncv_lfs_file_seek(&_lfs, &file_entity->lfs_file, offset, _lfs_from_whence(whence));
    return _lfs_to_error(res);
}

off_t FMLittleFileSystem2::file_tell(fs_file_t file)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    off_t res = vznncv_lfs_file_tell(&_lfs, &file_entity->lfs_file);
    return _lfs_to_error(res);
}

off_t FMLittleFileSystem2::file_size(fs_file_t file)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    off_t res = vznncv_lfs_file_size(&_lfs, &file_entity->lfs_file);
    return _lfs_to_error(res);
}

int FMLittleFileSystem2::file_truncate(fs_file_t file, off_t length)
{
    mbed_lock_guard lck(_mutex);
    file_entity_t *file_entity = (file_entity_t *)file;
    int err = vznncv_lfs_file_truncate(&_lfs, &file_entity->lfs_file, length);
    return _lfs_to_error(err);
}

//
// Dir operations
//
int FMLittleFileSystem2::dir_open(fs_dir_t *dir, const char *path)
{
    mbed_lock_guard lck(_mutex);

    // allocate memory block
    dir_entity_t *d = _active_dir_entity;
    if (d == nullptr) {
        d = _dir_entity_pool->allocate();
        if (d == nullptr) {
            return -EMFILE;
        }
    }

    // open directory
    int err = vznncv_lfs_dir_open(&_lfs, &d->lfs_dir, path);
    if (!err) {
        *dir = d;
    } else if (_active_dir_entity == nullptr) {
        _dir_entity_pool->deallocate(d);
    }

    return _lfs_to_error(err);
}

int FMLittleFileSystem2::dir_close(fs_dir_t dir)
{
    dir_entity_t *d = (dir_entity_t *)dir;
    mbed_lock_guard lck(_mutex);

    int err = vznncv_lfs_dir_close(&_lfs, &d->lfs_dir);

    // deallocate memory block
    if (_active_dir_entity == nullptr) {
        _dir_entity_pool->deallocate(d);
    }

    return _lfs_to_error(err);
}

ssize_t FMLittleFileSystem2::dir_read(fs_dir_t dir, struct dirent *ent)
{
    dir_entity_t *d = (dir_entity_t *)dir;
    mbed_lock_guard lck(_mutex);

    int res = vznncv_lfs_dir_read(&_lfs, &d->lfs_dir, &_lfs_info);
    if (res == 1) {
        ent->d_type = vznncv_lfs_totype(_lfs_info.type);
        strcpy(ent->d_name, _lfs_info.name);
    }
    return _lfs_to_error(res);
}

void FMLittleFileSystem2::dir_seek(fs_dir_t dir, off_t offset)
{
    dir_entity_t *d = (dir_entity_t *)dir;
    mbed_lock_guard lck(_mutex);

    vznncv_lfs_dir_seek(&_lfs, &d->lfs_dir, offset);
}

off_t FMLittleFileSystem2::dir_tell(fs_dir_t dir)
{
    dir_entity_t *d = (dir_entity_t *)dir;
    mbed_lock_guard lck(_mutex);

    vznncv_lfs_soff_t res = vznncv_lfs_dir_tell(&_lfs, &d->lfs_dir);
    return _lfs_to_error(res);
}

void FMLittleFileSystem2::dir_rewind(fs_dir_t dir)
{
    dir_entity_t *d = (dir_entity_t *)dir;
    mbed_lock_guard lck(_mutex);

    vznncv_lfs_dir_rewind(&_lfs, &d->lfs_dir);
}

//
// Hooks for file system handle
//

int FMLittleFileSystem2::FileHandlerImpl::close()
{
    int err = File::close();

    FileEntityPool *pool = _pool;
    file_entity_t *file_entity = _file_entity;
    _pool = nullptr;
    _file_entity = nullptr;
    this->~FileHandlerImpl();
    pool->deallocate(file_entity);

    return err;
}

int FMLittleFileSystem2::open(FileHandle **file, const char *path, int flags)
{
    mbed_lock_guard lck(_mutex);
    MBED_ASSERT(_active_file_entity == nullptr);

    // allocate memory block
    _active_file_entity = _file_entity_pool->allocate();
    if (_active_file_entity == nullptr) {
        return -EMFILE;
    }

    // open file
    File *f = new (_active_file_entity->file_handle) FileHandlerImpl(_file_entity_pool, _active_file_entity);
    int err = f->open(this, path, flags);
    if (err) {
        f->~File();
        _file_entity_pool->deallocate(_active_file_entity);
    } else {
        *file = f;
    }

    _active_file_entity = nullptr;
    return err;
}

int FMLittleFileSystem2::DirHandlerImpl::close()
{
    int err = Dir::close();

    DirEntityPool *pool = _pool;
    dir_entity_t *dir_entity = _dir_entity;
    _pool = nullptr;
    _dir_entity = nullptr;
    this->~DirHandlerImpl();
    pool->deallocate(dir_entity);

    return err;
}
int FMLittleFileSystem2::open(DirHandle **dir, const char *path)
{
    mbed_lock_guard lck(_mutex);
    MBED_ASSERT(_active_dir_entity == nullptr);

    // allocate memory block
    _active_dir_entity = _dir_entity_pool->allocate();
    if (_active_dir_entity == nullptr) {
        return -EMFILE;
    }

    // open file
    Dir *d = new (_active_dir_entity->dir_handle) DirHandlerImpl(_dir_entity_pool, _active_dir_entity);
    int err = d->open(this, path);
    if (err) {
        d->~Dir();
        _dir_entity_pool->deallocate(_active_dir_entity);
    } else {
        *dir = d;
    }

    _active_dir_entity = nullptr;
    return err;
}
};

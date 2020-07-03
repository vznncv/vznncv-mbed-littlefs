/*
 * The little filesystem
 *
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "vznncv_lfs.h"
#include "vznncv_lfs_util.h"

#define VZNNCV_LFS_BLOCK_NULL ((vznncv_lfs_block_t)-1)
#define VZNNCV_LFS_BLOCK_INLINE ((vznncv_lfs_block_t)-2)

/// Caching block device operations ///
static inline void vznncv_lfs_cache_drop(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_cache_t *rcache) {
    // do not zero, cheaper if cache is readonly or only going to be
    // written with identical data (during relocates)
    (void)vznncv_lfs;
    rcache->block = VZNNCV_LFS_BLOCK_NULL;
}

static inline void vznncv_lfs_cache_zero(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_cache_t *pcache) {
    // zero to avoid information leak
    memset(pcache->buffer, 0xff, vznncv_lfs->cfg->cache_size);
    pcache->block = VZNNCV_LFS_BLOCK_NULL;
}

static int vznncv_lfs_bd_read(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache, vznncv_lfs_size_t hint,
        vznncv_lfs_block_t block, vznncv_lfs_off_t off,
        void *buffer, vznncv_lfs_size_t size) {
    uint8_t *data = buffer;
    if (block >= vznncv_lfs->cfg->block_count ||
            off+size > vznncv_lfs->cfg->block_size) {
        return VZNNCV_LFS_ERR_CORRUPT;
    }

    while (size > 0) {
        vznncv_lfs_size_t diff = size;

        if (pcache && block == pcache->block &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) {
                // is already in pcache?
                diff = vznncv_lfs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // pcache takes priority
            diff = vznncv_lfs_min(diff, pcache->off-off);
        }

        if (block == rcache->block &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) {
                // is already in rcache?
                diff = vznncv_lfs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // rcache takes priority
            diff = vznncv_lfs_min(diff, rcache->off-off);
        }

        if (size >= hint && off % vznncv_lfs->cfg->read_size == 0 &&
                size >= vznncv_lfs->cfg->read_size) {
            // bypass cache?
            diff = vznncv_lfs_aligndown(diff, vznncv_lfs->cfg->read_size);
            int err = vznncv_lfs->cfg->read(vznncv_lfs->cfg, block, off, data, diff);
            if (err) {
                return err;
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        // load to cache, first condition can no longer fail
        VZNNCV_LFS_ASSERT(block < vznncv_lfs->cfg->block_count);
        rcache->block = block;
        rcache->off = vznncv_lfs_aligndown(off, vznncv_lfs->cfg->read_size);
        rcache->size = vznncv_lfs_min(
                vznncv_lfs_min(
                    vznncv_lfs_alignup(off+hint, vznncv_lfs->cfg->read_size),
                    vznncv_lfs->cfg->block_size)
                - rcache->off,
                vznncv_lfs->cfg->cache_size);
        int err = vznncv_lfs->cfg->read(vznncv_lfs->cfg, rcache->block,
                rcache->off, rcache->buffer, rcache->size);
        VZNNCV_LFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }
    }

    return 0;
}

enum {
    VZNNCV_LFS_CMP_EQ = 0,
    VZNNCV_LFS_CMP_LT = 1,
    VZNNCV_LFS_CMP_GT = 2,
};

static int vznncv_lfs_bd_cmp(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache, vznncv_lfs_size_t hint,
        vznncv_lfs_block_t block, vznncv_lfs_off_t off,
        const void *buffer, vznncv_lfs_size_t size) {
    const uint8_t *data = buffer;

    for (vznncv_lfs_off_t i = 0; i < size; i++) {
        uint8_t dat;
        int err = vznncv_lfs_bd_read(vznncv_lfs,
                pcache, rcache, hint-i,
                block, off+i, &dat, 1);
        if (err) {
            return err;
        }

        if (dat != data[i]) {
            return (dat < data[i]) ? VZNNCV_LFS_CMP_LT : VZNNCV_LFS_CMP_GT;
        }
    }

    return VZNNCV_LFS_CMP_EQ;
}

static int vznncv_lfs_bd_flush(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache, bool validate) {
    if (pcache->block != VZNNCV_LFS_BLOCK_NULL && pcache->block != VZNNCV_LFS_BLOCK_INLINE) {
        VZNNCV_LFS_ASSERT(pcache->block < vznncv_lfs->cfg->block_count);
        vznncv_lfs_size_t diff = vznncv_lfs_alignup(pcache->size, vznncv_lfs->cfg->prog_size);
        int err = vznncv_lfs->cfg->prog(vznncv_lfs->cfg, pcache->block,
                pcache->off, pcache->buffer, diff);
        VZNNCV_LFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }

        if (validate) {
            // check data on disk
            vznncv_lfs_cache_drop(vznncv_lfs, rcache);
            int res = vznncv_lfs_bd_cmp(vznncv_lfs,
                    NULL, rcache, diff,
                    pcache->block, pcache->off, pcache->buffer, diff);
            if (res < 0) {
                return res;
            }

            if (res != VZNNCV_LFS_CMP_EQ) {
                return VZNNCV_LFS_ERR_CORRUPT;
            }
        }

        vznncv_lfs_cache_zero(vznncv_lfs, pcache);
    }

    return 0;
}

static int vznncv_lfs_bd_sync(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache, bool validate) {
    vznncv_lfs_cache_drop(vznncv_lfs, rcache);

    int err = vznncv_lfs_bd_flush(vznncv_lfs, pcache, rcache, validate);
    if (err) {
        return err;
    }

    err = vznncv_lfs->cfg->sync(vznncv_lfs->cfg);
    VZNNCV_LFS_ASSERT(err <= 0);
    return err;
}

static int vznncv_lfs_bd_prog(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache, bool validate,
        vznncv_lfs_block_t block, vznncv_lfs_off_t off,
        const void *buffer, vznncv_lfs_size_t size) {
    const uint8_t *data = buffer;
    VZNNCV_LFS_ASSERT(block == VZNNCV_LFS_BLOCK_INLINE || block < vznncv_lfs->cfg->block_count);
    VZNNCV_LFS_ASSERT(off + size <= vznncv_lfs->cfg->block_size);

    while (size > 0) {
        if (block == pcache->block &&
                off >= pcache->off &&
                off < pcache->off + vznncv_lfs->cfg->cache_size) {
            // already fits in pcache?
            vznncv_lfs_size_t diff = vznncv_lfs_min(size,
                    vznncv_lfs->cfg->cache_size - (off-pcache->off));
            memcpy(&pcache->buffer[off-pcache->off], data, diff);

            data += diff;
            off += diff;
            size -= diff;

            pcache->size = vznncv_lfs_max(pcache->size, off - pcache->off);
            if (pcache->size == vznncv_lfs->cfg->cache_size) {
                // eagerly flush out pcache if we fill up
                int err = vznncv_lfs_bd_flush(vznncv_lfs, pcache, rcache, validate);
                if (err) {
                    return err;
                }
            }

            continue;
        }

        // pcache must have been flushed, either by programming and
        // entire block or manually flushing the pcache
        VZNNCV_LFS_ASSERT(pcache->block == VZNNCV_LFS_BLOCK_NULL);

        // prepare pcache, first condition can no longer fail
        pcache->block = block;
        pcache->off = vznncv_lfs_aligndown(off, vznncv_lfs->cfg->prog_size);
        pcache->size = 0;
    }

    return 0;
}

static int vznncv_lfs_bd_erase(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_block_t block) {
    VZNNCV_LFS_ASSERT(block < vznncv_lfs->cfg->block_count);
    int err = vznncv_lfs->cfg->erase(vznncv_lfs->cfg, block);
    VZNNCV_LFS_ASSERT(err <= 0);
    return err;
}


/// Small type-level utilities ///
// operations on block pairs
static inline void vznncv_lfs_pair_swap(vznncv_lfs_block_t pair[2]) {
    vznncv_lfs_block_t t = pair[0];
    pair[0] = pair[1];
    pair[1] = t;
}

static inline bool vznncv_lfs_pair_isnull(const vznncv_lfs_block_t pair[2]) {
    return pair[0] == VZNNCV_LFS_BLOCK_NULL || pair[1] == VZNNCV_LFS_BLOCK_NULL;
}

static inline int vznncv_lfs_pair_cmp(
        const vznncv_lfs_block_t paira[2],
        const vznncv_lfs_block_t pairb[2]) {
    return !(paira[0] == pairb[0] || paira[1] == pairb[1] ||
             paira[0] == pairb[1] || paira[1] == pairb[0]);
}

static inline bool vznncv_lfs_pair_sync(
        const vznncv_lfs_block_t paira[2],
        const vznncv_lfs_block_t pairb[2]) {
    return (paira[0] == pairb[0] && paira[1] == pairb[1]) ||
           (paira[0] == pairb[1] && paira[1] == pairb[0]);
}

static inline void vznncv_lfs_pair_fromle32(vznncv_lfs_block_t pair[2]) {
    pair[0] = vznncv_lfs_fromle32(pair[0]);
    pair[1] = vznncv_lfs_fromle32(pair[1]);
}

static inline void vznncv_lfs_pair_tole32(vznncv_lfs_block_t pair[2]) {
    pair[0] = vznncv_lfs_tole32(pair[0]);
    pair[1] = vznncv_lfs_tole32(pair[1]);
}

// operations on 32-bit entry tags
typedef uint32_t vznncv_lfs_tag_t;
typedef int32_t vznncv_lfs_stag_t;

#define VZNNCV_LFS_MKTAG(type, id, size) \
    (((vznncv_lfs_tag_t)(type) << 20) | ((vznncv_lfs_tag_t)(id) << 10) | (vznncv_lfs_tag_t)(size))

#define VZNNCV_LFS_MKTAG_IF(cond, type, id, size) \
    ((cond) ? VZNNCV_LFS_MKTAG(type, id, size) : VZNNCV_LFS_MKTAG(VZNNCV_LFS_FROM_NOOP, 0, 0))

#define VZNNCV_LFS_MKTAG_IF_ELSE(cond, type1, id1, size1, type2, id2, size2) \
    ((cond) ? VZNNCV_LFS_MKTAG(type1, id1, size1) : VZNNCV_LFS_MKTAG(type2, id2, size2))

static inline bool vznncv_lfs_tag_isvalid(vznncv_lfs_tag_t tag) {
    return !(tag & 0x80000000);
}

static inline bool vznncv_lfs_tag_isdelete(vznncv_lfs_tag_t tag) {
    return ((int32_t)(tag << 22) >> 22) == -1;
}

static inline uint16_t vznncv_lfs_tag_type1(vznncv_lfs_tag_t tag) {
    return (tag & 0x70000000) >> 20;
}

static inline uint16_t vznncv_lfs_tag_type3(vznncv_lfs_tag_t tag) {
    return (tag & 0x7ff00000) >> 20;
}

static inline uint8_t vznncv_lfs_tag_chunk(vznncv_lfs_tag_t tag) {
    return (tag & 0x0ff00000) >> 20;
}

static inline int8_t vznncv_lfs_tag_splice(vznncv_lfs_tag_t tag) {
    return (int8_t)vznncv_lfs_tag_chunk(tag);
}

static inline uint16_t vznncv_lfs_tag_id(vznncv_lfs_tag_t tag) {
    return (tag & 0x000ffc00) >> 10;
}

static inline vznncv_lfs_size_t vznncv_lfs_tag_size(vznncv_lfs_tag_t tag) {
    return tag & 0x000003ff;
}

static inline vznncv_lfs_size_t vznncv_lfs_tag_dsize(vznncv_lfs_tag_t tag) {
    return sizeof(tag) + vznncv_lfs_tag_size(tag + vznncv_lfs_tag_isdelete(tag));
}

// operations on attributes in attribute lists
struct vznncv_lfs_mattr {
    vznncv_lfs_tag_t tag;
    const void *buffer;
};

struct vznncv_lfs_diskoff {
    vznncv_lfs_block_t block;
    vznncv_lfs_off_t off;
};

#define VZNNCV_LFS_MKATTRS(...) \
    (struct vznncv_lfs_mattr[]){__VA_ARGS__}, \
    sizeof((struct vznncv_lfs_mattr[]){__VA_ARGS__}) / sizeof(struct vznncv_lfs_mattr)

// operations on global state
static inline void vznncv_lfs_gstate_xor(vznncv_lfs_gstate_t *a, const vznncv_lfs_gstate_t *b) {
    for (int i = 0; i < 3; i++) {
        ((uint32_t*)a)[i] ^= ((const uint32_t*)b)[i];
    }
}

static inline bool vznncv_lfs_gstate_iszero(const vznncv_lfs_gstate_t *a) {
    for (int i = 0; i < 3; i++) {
        if (((uint32_t*)a)[i] != 0) {
            return false;
        }
    }
    return true;
}

static inline bool vznncv_lfs_gstate_hasorphans(const vznncv_lfs_gstate_t *a) {
    return vznncv_lfs_tag_size(a->tag);
}

static inline uint8_t vznncv_lfs_gstate_getorphans(const vznncv_lfs_gstate_t *a) {
    return vznncv_lfs_tag_size(a->tag);
}

static inline bool vznncv_lfs_gstate_hasmove(const vznncv_lfs_gstate_t *a) {
    return vznncv_lfs_tag_type1(a->tag);
}

static inline bool vznncv_lfs_gstate_hasmovehere(const vznncv_lfs_gstate_t *a,
        const vznncv_lfs_block_t *pair) {
    return vznncv_lfs_tag_type1(a->tag) && vznncv_lfs_pair_cmp(a->pair, pair) == 0;
}

static inline void vznncv_lfs_gstate_fromle32(vznncv_lfs_gstate_t *a) {
    a->tag     = vznncv_lfs_fromle32(a->tag);
    a->pair[0] = vznncv_lfs_fromle32(a->pair[0]);
    a->pair[1] = vznncv_lfs_fromle32(a->pair[1]);
}

static inline void vznncv_lfs_gstate_tole32(vznncv_lfs_gstate_t *a) {
    a->tag     = vznncv_lfs_tole32(a->tag);
    a->pair[0] = vznncv_lfs_tole32(a->pair[0]);
    a->pair[1] = vznncv_lfs_tole32(a->pair[1]);
}

// other endianness operations
static void vznncv_lfs_ctz_fromle32(struct vznncv_lfs_ctz *ctz) {
    ctz->head = vznncv_lfs_fromle32(ctz->head);
    ctz->size = vznncv_lfs_fromle32(ctz->size);
}

static void vznncv_lfs_ctz_tole32(struct vznncv_lfs_ctz *ctz) {
    ctz->head = vznncv_lfs_tole32(ctz->head);
    ctz->size = vznncv_lfs_tole32(ctz->size);
}

static inline void vznncv_lfs_superblock_fromle32(vznncv_lfs_superblock_t *superblock) {
    superblock->version     = vznncv_lfs_fromle32(superblock->version);
    superblock->block_size  = vznncv_lfs_fromle32(superblock->block_size);
    superblock->block_count = vznncv_lfs_fromle32(superblock->block_count);
    superblock->name_max    = vznncv_lfs_fromle32(superblock->name_max);
    superblock->file_max    = vznncv_lfs_fromle32(superblock->file_max);
    superblock->attr_max    = vznncv_lfs_fromle32(superblock->attr_max);
}

static inline void vznncv_lfs_superblock_tole32(vznncv_lfs_superblock_t *superblock) {
    superblock->version     = vznncv_lfs_tole32(superblock->version);
    superblock->block_size  = vznncv_lfs_tole32(superblock->block_size);
    superblock->block_count = vznncv_lfs_tole32(superblock->block_count);
    superblock->name_max    = vznncv_lfs_tole32(superblock->name_max);
    superblock->file_max    = vznncv_lfs_tole32(superblock->file_max);
    superblock->attr_max    = vznncv_lfs_tole32(superblock->attr_max);
}


/// Internal operations predeclared here ///
static int vznncv_lfs_dir_commit(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_mdir_t *dir,
        const struct vznncv_lfs_mattr *attrs, int attrcount);
static int vznncv_lfs_dir_compact(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_mdir_t *dir, const struct vznncv_lfs_mattr *attrs, int attrcount,
        vznncv_lfs_mdir_t *source, uint16_t begin, uint16_t end);
static int vznncv_lfs_file_outline(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file);
static int vznncv_lfs_file_flush(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file);
static void vznncv_lfs_fs_preporphans(vznncv_lfs_t *vznncv_lfs, int8_t orphans);
static void vznncv_lfs_fs_prepmove(vznncv_lfs_t *vznncv_lfs,
        uint16_t id, const vznncv_lfs_block_t pair[2]);
static int vznncv_lfs_fs_pred(vznncv_lfs_t *vznncv_lfs, const vznncv_lfs_block_t dir[2],
        vznncv_lfs_mdir_t *pdir);
static vznncv_lfs_stag_t vznncv_lfs_fs_parent(vznncv_lfs_t *vznncv_lfs, const vznncv_lfs_block_t dir[2],
        vznncv_lfs_mdir_t *parent);
static int vznncv_lfs_fs_relocate(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_block_t oldpair[2], vznncv_lfs_block_t newpair[2]);
int vznncv_lfs_fs_traverseraw(vznncv_lfs_t *vznncv_lfs,
        int (*cb)(void *data, vznncv_lfs_block_t block), void *data,
        bool includeorphans);
static int vznncv_lfs_fs_forceconsistency(vznncv_lfs_t *vznncv_lfs);
static int vznncv_lfs_deinit(vznncv_lfs_t *vznncv_lfs);
#ifdef VZNNCV_LFS_MIGRATE
static int vznncv_lfs1_traverse(vznncv_lfs_t *vznncv_lfs,
        int (*cb)(void*, vznncv_lfs_block_t), void *data);
#endif

/// Block allocator ///
static int vznncv_lfs_alloc_lookahead(void *p, vznncv_lfs_block_t block) {
    vznncv_lfs_t *vznncv_lfs = (vznncv_lfs_t*)p;
    vznncv_lfs_block_t off = ((block - vznncv_lfs->free.off)
            + vznncv_lfs->cfg->block_count) % vznncv_lfs->cfg->block_count;

    if (off < vznncv_lfs->free.size) {
        vznncv_lfs->free.buffer[off / 32] |= 1U << (off % 32);
    }

    return 0;
}

static void vznncv_lfs_alloc_ack(vznncv_lfs_t *vznncv_lfs) {
    vznncv_lfs->free.ack = vznncv_lfs->cfg->block_count;
}

// Invalidate the lookahead buffer. This is done during mounting and
// failed traversals
static void vznncv_lfs_alloc_reset(vznncv_lfs_t *vznncv_lfs) {
    vznncv_lfs->free.off = vznncv_lfs->seed % vznncv_lfs->cfg->block_size;
    vznncv_lfs->free.size = 0;
    vznncv_lfs->free.i = 0;
    vznncv_lfs_alloc_ack(vznncv_lfs);
}

static int vznncv_lfs_alloc(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_block_t *block) {
    while (true) {
        while (vznncv_lfs->free.i != vznncv_lfs->free.size) {
            vznncv_lfs_block_t off = vznncv_lfs->free.i;
            vznncv_lfs->free.i += 1;
            vznncv_lfs->free.ack -= 1;

            if (!(vznncv_lfs->free.buffer[off / 32] & (1U << (off % 32)))) {
                // found a free block
                *block = (vznncv_lfs->free.off + off) % vznncv_lfs->cfg->block_count;

                // eagerly find next off so an alloc ack can
                // discredit old lookahead blocks
                while (vznncv_lfs->free.i != vznncv_lfs->free.size &&
                        (vznncv_lfs->free.buffer[vznncv_lfs->free.i / 32]
                            & (1U << (vznncv_lfs->free.i % 32)))) {
                    vznncv_lfs->free.i += 1;
                    vznncv_lfs->free.ack -= 1;
                }

                return 0;
            }
        }

        // check if we have looked at all blocks since last ack
        if (vznncv_lfs->free.ack == 0) {
            VZNNCV_LFS_ERROR("No more free space %"PRIu32,
                    vznncv_lfs->free.i + vznncv_lfs->free.off);
            return VZNNCV_LFS_ERR_NOSPC;
        }

        vznncv_lfs->free.off = (vznncv_lfs->free.off + vznncv_lfs->free.size)
                % vznncv_lfs->cfg->block_count;
        vznncv_lfs->free.size = vznncv_lfs_min(8*vznncv_lfs->cfg->lookahead_size, vznncv_lfs->free.ack);
        vznncv_lfs->free.i = 0;

        // find mask of free blocks from tree
        memset(vznncv_lfs->free.buffer, 0, vznncv_lfs->cfg->lookahead_size);
        int err = vznncv_lfs_fs_traverseraw(vznncv_lfs, vznncv_lfs_alloc_lookahead, vznncv_lfs, true);
        if (err) {
            vznncv_lfs_alloc_reset(vznncv_lfs);
            return err;
        }
    }
}

/// Metadata pair and directory operations ///
static vznncv_lfs_stag_t vznncv_lfs_dir_getslice(vznncv_lfs_t *vznncv_lfs, const vznncv_lfs_mdir_t *dir,
        vznncv_lfs_tag_t gmask, vznncv_lfs_tag_t gtag,
        vznncv_lfs_off_t goff, void *gbuffer, vznncv_lfs_size_t gsize) {
    vznncv_lfs_off_t off = dir->off;
    vznncv_lfs_tag_t ntag = dir->etag;
    vznncv_lfs_stag_t gdiff = 0;

    if (vznncv_lfs_gstate_hasmovehere(&vznncv_lfs->gdisk, dir->pair) &&
            vznncv_lfs_tag_id(gmask) != 0 &&
            vznncv_lfs_tag_id(vznncv_lfs->gdisk.tag) <= vznncv_lfs_tag_id(gtag)) {
        // synthetic moves
        gdiff -= VZNNCV_LFS_MKTAG(0, 1, 0);
    }

    // iterate over dir block backwards (for faster lookups)
    while (off >= sizeof(vznncv_lfs_tag_t) + vznncv_lfs_tag_dsize(ntag)) {
        off -= vznncv_lfs_tag_dsize(ntag);
        vznncv_lfs_tag_t tag = ntag;
        int err = vznncv_lfs_bd_read(vznncv_lfs,
                NULL, &vznncv_lfs->rcache, sizeof(ntag),
                dir->pair[0], off, &ntag, sizeof(ntag));
        if (err) {
            return err;
        }

        ntag = (vznncv_lfs_frombe32(ntag) ^ tag) & 0x7fffffff;

        if (vznncv_lfs_tag_id(gmask) != 0 &&
                vznncv_lfs_tag_type1(tag) == VZNNCV_LFS_TYPE_SPLICE &&
                vznncv_lfs_tag_id(tag) <= vznncv_lfs_tag_id(gtag - gdiff)) {
            if (tag == (VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CREATE, 0, 0) |
                    (VZNNCV_LFS_MKTAG(0, 0x3ff, 0) & (gtag - gdiff)))) {
                // found where we were created
                return VZNNCV_LFS_ERR_NOENT;
            }

            // move around splices
            gdiff += VZNNCV_LFS_MKTAG(0, vznncv_lfs_tag_splice(tag), 0);
        }

        if ((gmask & tag) == (gmask & (gtag - gdiff))) {
            if (vznncv_lfs_tag_isdelete(tag)) {
                return VZNNCV_LFS_ERR_NOENT;
            }

            vznncv_lfs_size_t diff = vznncv_lfs_min(vznncv_lfs_tag_size(tag), gsize);
            err = vznncv_lfs_bd_read(vznncv_lfs,
                    NULL, &vznncv_lfs->rcache, diff,
                    dir->pair[0], off+sizeof(tag)+goff, gbuffer, diff);
            if (err) {
                return err;
            }

            memset((uint8_t*)gbuffer + diff, 0, gsize - diff);

            return tag + gdiff;
        }
    }

    return VZNNCV_LFS_ERR_NOENT;
}

static vznncv_lfs_stag_t vznncv_lfs_dir_get(vznncv_lfs_t *vznncv_lfs, const vznncv_lfs_mdir_t *dir,
        vznncv_lfs_tag_t gmask, vznncv_lfs_tag_t gtag, void *buffer) {
    return vznncv_lfs_dir_getslice(vznncv_lfs, dir,
            gmask, gtag,
            0, buffer, vznncv_lfs_tag_size(gtag));
}

static int vznncv_lfs_dir_getread(vznncv_lfs_t *vznncv_lfs, const vznncv_lfs_mdir_t *dir,
        const vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache, vznncv_lfs_size_t hint,
        vznncv_lfs_tag_t gmask, vznncv_lfs_tag_t gtag,
        vznncv_lfs_off_t off, void *buffer, vznncv_lfs_size_t size) {
    uint8_t *data = buffer;
    if (off+size > vznncv_lfs->cfg->block_size) {
        return VZNNCV_LFS_ERR_CORRUPT;
    }

    while (size > 0) {
        vznncv_lfs_size_t diff = size;

        if (pcache && pcache->block == VZNNCV_LFS_BLOCK_INLINE &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) {
                // is already in pcache?
                diff = vznncv_lfs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // pcache takes priority
            diff = vznncv_lfs_min(diff, pcache->off-off);
        }

        if (rcache->block == VZNNCV_LFS_BLOCK_INLINE &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) {
                // is already in rcache?
                diff = vznncv_lfs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            // rcache takes priority
            diff = vznncv_lfs_min(diff, rcache->off-off);
        }

        // load to cache, first condition can no longer fail
        rcache->block = VZNNCV_LFS_BLOCK_INLINE;
        rcache->off = vznncv_lfs_aligndown(off, vznncv_lfs->cfg->read_size);
        rcache->size = vznncv_lfs_min(vznncv_lfs_alignup(off+hint, vznncv_lfs->cfg->read_size),
                vznncv_lfs->cfg->cache_size);
        int err = vznncv_lfs_dir_getslice(vznncv_lfs, dir, gmask, gtag,
                rcache->off, rcache->buffer, rcache->size);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

static int vznncv_lfs_dir_traverse_filter(void *p,
        vznncv_lfs_tag_t tag, const void *buffer) {
    vznncv_lfs_tag_t *filtertag = p;
    (void)buffer;

    // which mask depends on unique bit in tag structure
    uint32_t mask = (tag & VZNNCV_LFS_MKTAG(0x100, 0, 0))
            ? VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0)
            : VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0);

    // check for redundancy
    if ((mask & tag) == (mask & *filtertag) ||
            vznncv_lfs_tag_isdelete(*filtertag) ||
            (VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0) & tag) == (
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DELETE, 0, 0) |
                    (VZNNCV_LFS_MKTAG(0, 0x3ff, 0) & *filtertag))) {
        return true;
    }

    // check if we need to adjust for created/deleted tags
    if (vznncv_lfs_tag_type1(tag) == VZNNCV_LFS_TYPE_SPLICE &&
            vznncv_lfs_tag_id(tag) <= vznncv_lfs_tag_id(*filtertag)) {
        *filtertag += VZNNCV_LFS_MKTAG(0, vznncv_lfs_tag_splice(tag), 0);
    }

    return false;
}

static int vznncv_lfs_dir_traverse(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_mdir_t *dir, vznncv_lfs_off_t off, vznncv_lfs_tag_t ptag,
        const struct vznncv_lfs_mattr *attrs, int attrcount,
        vznncv_lfs_tag_t tmask, vznncv_lfs_tag_t ttag,
        uint16_t begin, uint16_t end, int16_t diff,
        int (*cb)(void *data, vznncv_lfs_tag_t tag, const void *buffer), void *data) {
    // iterate over directory and attrs
    while (true) {
        vznncv_lfs_tag_t tag;
        const void *buffer;
        struct vznncv_lfs_diskoff disk;
        if (off+vznncv_lfs_tag_dsize(ptag) < dir->off) {
            off += vznncv_lfs_tag_dsize(ptag);
            int err = vznncv_lfs_bd_read(vznncv_lfs,
                    NULL, &vznncv_lfs->rcache, sizeof(tag),
                    dir->pair[0], off, &tag, sizeof(tag));
            if (err) {
                return err;
            }

            tag = (vznncv_lfs_frombe32(tag) ^ ptag) | 0x80000000;
            disk.block = dir->pair[0];
            disk.off = off+sizeof(vznncv_lfs_tag_t);
            buffer = &disk;
            ptag = tag;
        } else if (attrcount > 0) {
            tag = attrs[0].tag;
            buffer = attrs[0].buffer;
            attrs += 1;
            attrcount -= 1;
        } else {
            return 0;
        }

        vznncv_lfs_tag_t mask = VZNNCV_LFS_MKTAG(0x7ff, 0, 0);
        if ((mask & tmask & tag) != (mask & tmask & ttag)) {
            continue;
        }

        // do we need to filter? inlining the filtering logic here allows
        // for some minor optimizations
        if (vznncv_lfs_tag_id(tmask) != 0) {
            // scan for duplicates and update tag based on creates/deletes
            int filter = vznncv_lfs_dir_traverse(vznncv_lfs,
                    dir, off, ptag, attrs, attrcount,
                    0, 0, 0, 0, 0,
                    vznncv_lfs_dir_traverse_filter, &tag);
            if (filter < 0) {
                return filter;
            }

            if (filter) {
                continue;
            }

            // in filter range?
            if (!(vznncv_lfs_tag_id(tag) >= begin && vznncv_lfs_tag_id(tag) < end)) {
                continue;
            }
        }

        // handle special cases for mcu-side operations
        if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_FROM_NOOP) {
            // do nothing
        } else if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_FROM_MOVE) {
            uint16_t fromid = vznncv_lfs_tag_size(tag);
            uint16_t toid = vznncv_lfs_tag_id(tag);
            int err = vznncv_lfs_dir_traverse(vznncv_lfs,
                    buffer, 0, 0xffffffff, NULL, 0,
                    VZNNCV_LFS_MKTAG(0x600, 0x3ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, 0, 0),
                    fromid, fromid+1, toid-fromid+diff,
                    cb, data);
            if (err) {
                return err;
            }
        } else if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_FROM_USERATTRS) {
            for (unsigned i = 0; i < vznncv_lfs_tag_size(tag); i++) {
                const struct vznncv_lfs_attr *a = buffer;
                int err = cb(data, VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_USERATTR + a[i].type,
                        vznncv_lfs_tag_id(tag) + diff, a[i].size), a[i].buffer);
                if (err) {
                    return err;
                }
            }
        } else {
            int err = cb(data, tag + VZNNCV_LFS_MKTAG(0, diff, 0), buffer);
            if (err) {
                return err;
            }
        }
    }
}

static vznncv_lfs_stag_t vznncv_lfs_dir_fetchmatch(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_mdir_t *dir, const vznncv_lfs_block_t pair[2],
        vznncv_lfs_tag_t fmask, vznncv_lfs_tag_t ftag, uint16_t *id,
        int (*cb)(void *data, vznncv_lfs_tag_t tag, const void *buffer), void *data) {
    // we can find tag very efficiently during a fetch, since we're already
    // scanning the entire directory
    vznncv_lfs_stag_t besttag = -1;

    // if either block address is invalid we return VZNNCV_LFS_ERR_CORRUPT here,
    // otherwise later writes to the pair could fail
    if (pair[0] >= vznncv_lfs->cfg->block_count || pair[1] >= vznncv_lfs->cfg->block_count) {
        return VZNNCV_LFS_ERR_CORRUPT;
    }

    // find the block with the most recent revision
    uint32_t revs[2] = {0, 0};
    int r = 0;
    for (int i = 0; i < 2; i++) {
        int err = vznncv_lfs_bd_read(vznncv_lfs,
                NULL, &vznncv_lfs->rcache, sizeof(revs[i]),
                pair[i], 0, &revs[i], sizeof(revs[i]));
        revs[i] = vznncv_lfs_fromle32(revs[i]);
        if (err && err != VZNNCV_LFS_ERR_CORRUPT) {
            return err;
        }

        if (err != VZNNCV_LFS_ERR_CORRUPT &&
                vznncv_lfs_scmp(revs[i], revs[(i+1)%2]) > 0) {
            r = i;
        }
    }

    dir->pair[0] = pair[(r+0)%2];
    dir->pair[1] = pair[(r+1)%2];
    dir->rev = revs[(r+0)%2];
    dir->off = 0; // nonzero = found some commits

    // now scan tags to fetch the actual dir and find possible match
    for (int i = 0; i < 2; i++) {
        vznncv_lfs_off_t off = 0;
        vznncv_lfs_tag_t ptag = 0xffffffff;

        uint16_t tempcount = 0;
#ifdef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_COMMIT_COMPACT_THRESHOLD
        uint16_t temp_commit_count = 0;
#endif
        vznncv_lfs_block_t temptail[2] = {VZNNCV_LFS_BLOCK_NULL, VZNNCV_LFS_BLOCK_NULL};
        bool tempsplit = false;
        vznncv_lfs_stag_t tempbesttag = besttag;

        dir->rev = vznncv_lfs_tole32(dir->rev);
        uint32_t crc = vznncv_lfs_crc(0xffffffff, &dir->rev, sizeof(dir->rev));
        dir->rev = vznncv_lfs_fromle32(dir->rev);

        while (true) {
            // extract next tag
            vznncv_lfs_tag_t tag;
            off += vznncv_lfs_tag_dsize(ptag);
            int err = vznncv_lfs_bd_read(vznncv_lfs,
                    NULL, &vznncv_lfs->rcache, vznncv_lfs->cfg->block_size,
                    dir->pair[0], off, &tag, sizeof(tag));
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    // can't continue?
                    dir->erased = false;
                    break;
                }
                return err;
            }

            crc = vznncv_lfs_crc(crc, &tag, sizeof(tag));
            tag = vznncv_lfs_frombe32(tag) ^ ptag;

            // next commit not yet programmed or we're not in valid range
            if (!vznncv_lfs_tag_isvalid(tag)) {
                dir->erased = (vznncv_lfs_tag_type1(ptag) == VZNNCV_LFS_TYPE_CRC &&
                        dir->off % vznncv_lfs->cfg->prog_size == 0);
                break;
            } else if (off + vznncv_lfs_tag_dsize(tag) > vznncv_lfs->cfg->block_size) {
                dir->erased = false;
                break;
            }

            ptag = tag;

            if (vznncv_lfs_tag_type1(tag) == VZNNCV_LFS_TYPE_CRC) {
                // check the crc attr
                uint32_t dcrc;
                err = vznncv_lfs_bd_read(vznncv_lfs,
                        NULL, &vznncv_lfs->rcache, vznncv_lfs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &dcrc, sizeof(dcrc));
                if (err) {
                    if (err == VZNNCV_LFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return err;
                }
                dcrc = vznncv_lfs_fromle32(dcrc);

                if (crc != dcrc) {
                    dir->erased = false;
                    break;
                }

                // reset the next bit if we need to
                ptag ^= (vznncv_lfs_tag_t)(vznncv_lfs_tag_chunk(tag) & 1U) << 31;

                // toss our crc into the filesystem seed for
                // pseudorandom numbers
                vznncv_lfs->seed ^= crc;

                // update with what's found so far
                besttag = tempbesttag;
                dir->off = off + vznncv_lfs_tag_dsize(tag);
                dir->etag = ptag;
                dir->count = tempcount;
                dir->tail[0] = temptail[0];
                dir->tail[1] = temptail[1];
                dir->split = tempsplit;

#ifdef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_COMMIT_COMPACT_THRESHOLD
                // update commit count
                temp_commit_count++;
                dir->commit_count = temp_commit_count;
#endif

                // reset crc
                crc = 0xffffffff;
                continue;
            }

            // crc the entry first, hopefully leaving it in the cache
            for (vznncv_lfs_off_t j = sizeof(tag); j < vznncv_lfs_tag_dsize(tag); j++) {
                uint8_t dat;
                err = vznncv_lfs_bd_read(vznncv_lfs,
                        NULL, &vznncv_lfs->rcache, vznncv_lfs->cfg->block_size,
                        dir->pair[0], off+j, &dat, 1);
                if (err) {
                    if (err == VZNNCV_LFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return err;
                }

                crc = vznncv_lfs_crc(crc, &dat, 1);
            }

            // directory modification tags?
            if (vznncv_lfs_tag_type1(tag) == VZNNCV_LFS_TYPE_NAME) {
                // increase count of files if necessary
                if (vznncv_lfs_tag_id(tag) >= tempcount) {
                    tempcount = vznncv_lfs_tag_id(tag) + 1;
                }
            } else if (vznncv_lfs_tag_type1(tag) == VZNNCV_LFS_TYPE_SPLICE) {
                tempcount += vznncv_lfs_tag_splice(tag);

                if (tag == (VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DELETE, 0, 0) |
                        (VZNNCV_LFS_MKTAG(0, 0x3ff, 0) & tempbesttag))) {
                    tempbesttag |= 0x80000000;
                } else if (tempbesttag != -1 &&
                        vznncv_lfs_tag_id(tag) <= vznncv_lfs_tag_id(tempbesttag)) {
                    tempbesttag += VZNNCV_LFS_MKTAG(0, vznncv_lfs_tag_splice(tag), 0);
                }
            } else if (vznncv_lfs_tag_type1(tag) == VZNNCV_LFS_TYPE_TAIL) {
                tempsplit = (vznncv_lfs_tag_chunk(tag) & 1);

                err = vznncv_lfs_bd_read(vznncv_lfs,
                        NULL, &vznncv_lfs->rcache, vznncv_lfs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &temptail, 8);
                if (err) {
                    if (err == VZNNCV_LFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                }
                vznncv_lfs_pair_fromle32(temptail);
            }

            // found a match for our fetcher?
            if ((fmask & tag) == (fmask & ftag)) {
                int res = cb(data, tag, &(struct vznncv_lfs_diskoff){
                        dir->pair[0], off+sizeof(tag)});
                if (res < 0) {
                    if (res == VZNNCV_LFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return res;
                }

                if (res == VZNNCV_LFS_CMP_EQ) {
                    // found a match
                    tempbesttag = tag;
                } else if ((VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0) & tag) ==
                        (VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0) & tempbesttag)) {
                    // found an identical tag, but contents didn't match
                    // this must mean that our besttag has been overwritten
                    tempbesttag = -1;
                } else if (res == VZNNCV_LFS_CMP_GT &&
                        vznncv_lfs_tag_id(tag) <= vznncv_lfs_tag_id(tempbesttag)) {
                    // found a greater match, keep track to keep things sorted
                    tempbesttag = tag | 0x80000000;
                }
            }
        }

        // consider what we have good enough
        if (dir->off > 0) {
            // synthetic move
            if (vznncv_lfs_gstate_hasmovehere(&vznncv_lfs->gdisk, dir->pair)) {
                if (vznncv_lfs_tag_id(vznncv_lfs->gdisk.tag) == vznncv_lfs_tag_id(besttag)) {
                    besttag |= 0x80000000;
                } else if (besttag != -1 &&
                        vznncv_lfs_tag_id(vznncv_lfs->gdisk.tag) < vznncv_lfs_tag_id(besttag)) {
                    besttag -= VZNNCV_LFS_MKTAG(0, 1, 0);
                }
            }

            // found tag? or found best id?
            if (id) {
                *id = vznncv_lfs_min(vznncv_lfs_tag_id(besttag), dir->count);
            }

            if (vznncv_lfs_tag_isvalid(besttag)) {
                return besttag;
            } else if (vznncv_lfs_tag_id(besttag) < dir->count) {
                return VZNNCV_LFS_ERR_NOENT;
            } else {
                return 0;
            }
        }

        // failed, try the other block?
        vznncv_lfs_pair_swap(dir->pair);
        dir->rev = revs[(r+1)%2];
    }

    VZNNCV_LFS_ERROR("Corrupted dir pair at {0x%"PRIx32", 0x%"PRIx32"}",
            dir->pair[0], dir->pair[1]);
    return VZNNCV_LFS_ERR_CORRUPT;
}

static int vznncv_lfs_dir_fetch(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_mdir_t *dir, const vznncv_lfs_block_t pair[2]) {
    // note, mask=-1, tag=-1 can never match a tag since this
    // pattern has the invalid bit set
    return (int)vznncv_lfs_dir_fetchmatch(vznncv_lfs, dir, pair,
            (vznncv_lfs_tag_t)-1, (vznncv_lfs_tag_t)-1, NULL, NULL, NULL);
}

static int vznncv_lfs_dir_getgstate(vznncv_lfs_t *vznncv_lfs, const vznncv_lfs_mdir_t *dir,
        vznncv_lfs_gstate_t *gstate) {
    vznncv_lfs_gstate_t temp;
    vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, dir, VZNNCV_LFS_MKTAG(0x7ff, 0, 0),
            VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_MOVESTATE, 0, sizeof(temp)), &temp);
    if (res < 0 && res != VZNNCV_LFS_ERR_NOENT) {
        return res;
    }

    if (res != VZNNCV_LFS_ERR_NOENT) {
        // xor together to find resulting gstate
        vznncv_lfs_gstate_fromle32(&temp);
        vznncv_lfs_gstate_xor(gstate, &temp);
    }

    return 0;
}

static int vznncv_lfs_dir_getinfo(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_mdir_t *dir,
        uint16_t id, struct vznncv_lfs_info *info) {
    if (id == 0x3ff) {
        // special case for root
        strcpy(info->name, "/");
        info->type = VZNNCV_LFS_TYPE_DIR;
        return 0;
    }

    vznncv_lfs_stag_t tag = vznncv_lfs_dir_get(vznncv_lfs, dir, VZNNCV_LFS_MKTAG(0x780, 0x3ff, 0),
            VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_NAME, id, vznncv_lfs->name_max+1), info->name);
    if (tag < 0) {
        return (int)tag;
    }

    info->type = vznncv_lfs_tag_type3(tag);

    struct vznncv_lfs_ctz ctz;
    tag = vznncv_lfs_dir_get(vznncv_lfs, dir, VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
            VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
    if (tag < 0) {
        return (int)tag;
    }
    vznncv_lfs_ctz_fromle32(&ctz);

    if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_TYPE_CTZSTRUCT) {
        info->size = ctz.size;
    } else if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_TYPE_INLINESTRUCT) {
        info->size = vznncv_lfs_tag_size(tag);
    }

    return 0;
}

struct vznncv_lfs_dir_find_match {
    vznncv_lfs_t *vznncv_lfs;
    const void *name;
    vznncv_lfs_size_t size;
};

static int vznncv_lfs_dir_find_match(void *data,
        vznncv_lfs_tag_t tag, const void *buffer) {
    struct vznncv_lfs_dir_find_match *name = data;
    vznncv_lfs_t *vznncv_lfs = name->vznncv_lfs;
    const struct vznncv_lfs_diskoff *disk = buffer;

    // compare with disk
    vznncv_lfs_size_t diff = vznncv_lfs_min(name->size, vznncv_lfs_tag_size(tag));
    int res = vznncv_lfs_bd_cmp(vznncv_lfs,
            NULL, &vznncv_lfs->rcache, diff,
            disk->block, disk->off, name->name, diff);
    if (res != VZNNCV_LFS_CMP_EQ) {
        return res;
    }

    // only equal if our size is still the same
    if (name->size != vznncv_lfs_tag_size(tag)) {
        return (name->size < vznncv_lfs_tag_size(tag)) ? VZNNCV_LFS_CMP_LT : VZNNCV_LFS_CMP_GT;
    }

    // found a match!
    return VZNNCV_LFS_CMP_EQ;
}

static vznncv_lfs_stag_t vznncv_lfs_dir_find(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_mdir_t *dir,
        const char **path, uint16_t *id) {
    // we reduce path to a single name if we can find it
    const char *name = *path;
    if (id) {
        *id = 0x3ff;
    }

    // default to root dir
    vznncv_lfs_stag_t tag = VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DIR, 0x3ff, 0);
    dir->tail[0] = vznncv_lfs->root[0];
    dir->tail[1] = vznncv_lfs->root[1];

    while (true) {
nextname:
        // skip slashes
        name += strspn(name, "/");
        vznncv_lfs_size_t namelen = strcspn(name, "/");

        // skip '.' and root '..'
        if ((namelen == 1 && memcmp(name, ".", 1) == 0) ||
            (namelen == 2 && memcmp(name, "..", 2) == 0)) {
            name += namelen;
            goto nextname;
        }

        // skip if matched by '..' in name
        const char *suffix = name + namelen;
        vznncv_lfs_size_t sufflen;
        int depth = 1;
        while (true) {
            suffix += strspn(suffix, "/");
            sufflen = strcspn(suffix, "/");
            if (sufflen == 0) {
                break;
            }

            if (sufflen == 2 && memcmp(suffix, "..", 2) == 0) {
                depth -= 1;
                if (depth == 0) {
                    name = suffix + sufflen;
                    goto nextname;
                }
            } else {
                depth += 1;
            }

            suffix += sufflen;
        }

        // found path
        if (name[0] == '\0') {
            return tag;
        }

        // update what we've found so far
        *path = name;

        // only continue if we hit a directory
        if (vznncv_lfs_tag_type3(tag) != VZNNCV_LFS_TYPE_DIR) {
            return VZNNCV_LFS_ERR_NOTDIR;
        }

        // grab the entry data
        if (vznncv_lfs_tag_id(tag) != 0x3ff) {
            vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, dir, VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, vznncv_lfs_tag_id(tag), 8), dir->tail);
            if (res < 0) {
                return res;
            }
            vznncv_lfs_pair_fromle32(dir->tail);
        }

        // find entry matching name
        while (true) {
            tag = vznncv_lfs_dir_fetchmatch(vznncv_lfs, dir, dir->tail,
                    VZNNCV_LFS_MKTAG(0x780, 0, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_NAME, 0, namelen),
                     // are we last name?
                    (strchr(name, '/') == NULL) ? id : NULL,
                    vznncv_lfs_dir_find_match, &(struct vznncv_lfs_dir_find_match){
                        vznncv_lfs, name, namelen});
            if (tag < 0) {
                return tag;
            }

            if (tag) {
                break;
            }

            if (!dir->split) {
                return VZNNCV_LFS_ERR_NOENT;
            }
        }

        // to next name
        name += namelen;
    }
}

// commit logic
struct vznncv_lfs_commit {
    vznncv_lfs_block_t block;
    vznncv_lfs_off_t off;
    vznncv_lfs_tag_t ptag;
    uint32_t crc;

    vznncv_lfs_off_t begin;
    vznncv_lfs_off_t end;
};

static int vznncv_lfs_dir_commitprog(vznncv_lfs_t *vznncv_lfs, struct vznncv_lfs_commit *commit,
        const void *buffer, vznncv_lfs_size_t size) {
    int err = vznncv_lfs_bd_prog(vznncv_lfs,
            &vznncv_lfs->pcache, &vznncv_lfs->rcache, false,
            commit->block, commit->off ,
            (const uint8_t*)buffer, size);
    if (err) {
        return err;
    }

    commit->crc = vznncv_lfs_crc(commit->crc, buffer, size);
    commit->off += size;
    return 0;
}

static int vznncv_lfs_dir_commitattr(vznncv_lfs_t *vznncv_lfs, struct vznncv_lfs_commit *commit,
        vznncv_lfs_tag_t tag, const void *buffer) {
    // check if we fit
    vznncv_lfs_size_t dsize = vznncv_lfs_tag_dsize(tag);
    if (commit->off + dsize > commit->end) {
        return VZNNCV_LFS_ERR_NOSPC;
    }

    // write out tag
    vznncv_lfs_tag_t ntag = vznncv_lfs_tobe32((tag & 0x7fffffff) ^ commit->ptag);
    int err = vznncv_lfs_dir_commitprog(vznncv_lfs, commit, &ntag, sizeof(ntag));
    if (err) {
        return err;
    }

    if (!(tag & 0x80000000)) {
        // from memory
        err = vznncv_lfs_dir_commitprog(vznncv_lfs, commit, buffer, dsize-sizeof(tag));
        if (err) {
            return err;
        }
    } else {
        // from disk
        const struct vznncv_lfs_diskoff *disk = buffer;
        for (vznncv_lfs_off_t i = 0; i < dsize-sizeof(tag); i++) {
            // rely on caching to make this efficient
            uint8_t dat;
            err = vznncv_lfs_bd_read(vznncv_lfs,
                    NULL, &vznncv_lfs->rcache, dsize-sizeof(tag)-i,
                    disk->block, disk->off+i, &dat, 1);
            if (err) {
                return err;
            }

            err = vznncv_lfs_dir_commitprog(vznncv_lfs, commit, &dat, 1);
            if (err) {
                return err;
            }
        }
    }

    commit->ptag = tag & 0x7fffffff;
    return 0;
}

static int vznncv_lfs_dir_commitcrc(vznncv_lfs_t *vznncv_lfs, struct vznncv_lfs_commit *commit) {
    const vznncv_lfs_off_t off1 = commit->off;
    const uint32_t crc1 = commit->crc;
    // align to program units
    const vznncv_lfs_off_t end = vznncv_lfs_alignup(off1 + 2*sizeof(uint32_t),
            vznncv_lfs->cfg->prog_size);

    // create crc tags to fill up remainder of commit, note that
    // padding is not crced, which lets fetches skip padding but
    // makes committing a bit more complicated
    while (commit->off < end) {
        vznncv_lfs_off_t off = commit->off + sizeof(vznncv_lfs_tag_t);
        vznncv_lfs_off_t noff = vznncv_lfs_min(end - off, 0x3fe) + off;
        if (noff < end) {
            noff = vznncv_lfs_min(noff, end - 2*sizeof(uint32_t));
        }

        // read erased state from next program unit
        vznncv_lfs_tag_t tag = 0xffffffff;
        int err = vznncv_lfs_bd_read(vznncv_lfs,
                NULL, &vznncv_lfs->rcache, sizeof(tag),
                commit->block, noff, &tag, sizeof(tag));
        if (err && err != VZNNCV_LFS_ERR_CORRUPT) {
            return err;
        }

        // build crc tag
        bool reset = ~vznncv_lfs_frombe32(tag) >> 31;
        tag = VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CRC + reset, 0x3ff, noff - off);

        // write out crc
        uint32_t footer[2];
        footer[0] = vznncv_lfs_tobe32(tag ^ commit->ptag);
        commit->crc = vznncv_lfs_crc(commit->crc, &footer[0], sizeof(footer[0]));
        footer[1] = vznncv_lfs_tole32(commit->crc);
        err = vznncv_lfs_bd_prog(vznncv_lfs,
                &vznncv_lfs->pcache, &vznncv_lfs->rcache, false,
                commit->block, commit->off, &footer, sizeof(footer));
        if (err) {
            return err;
        }

        commit->off += sizeof(tag)+vznncv_lfs_tag_size(tag);
        commit->ptag = tag ^ ((vznncv_lfs_tag_t)reset << 31);
        commit->crc = 0xffffffff; // reset crc for next "commit"
    }

    // flush buffers
    int err = vznncv_lfs_bd_sync(vznncv_lfs, &vznncv_lfs->pcache, &vznncv_lfs->rcache, false);
    if (err) {
        return err;
    }

    // successful commit, check checksums to make sure
    vznncv_lfs_off_t off = commit->begin;
    vznncv_lfs_off_t noff = off1 + sizeof(uint32_t);
    while (off < end) {
        uint32_t crc = 0xffffffff;
        for (vznncv_lfs_off_t i = off; i < noff+sizeof(uint32_t); i++) {
            // check against written crc, may catch blocks that
            // become readonly and match our commit size exactly
            if (i == off1 && crc != crc1) {
                return VZNNCV_LFS_ERR_CORRUPT;
            }

            // leave it up to caching to make this efficient
            uint8_t dat;
            err = vznncv_lfs_bd_read(vznncv_lfs,
                    NULL, &vznncv_lfs->rcache, noff+sizeof(uint32_t)-i,
                    commit->block, i, &dat, 1);
            if (err) {
                return err;
            }

            crc = vznncv_lfs_crc(crc, &dat, 1);
        }

        // detected write error?
        if (crc != 0) {
            return VZNNCV_LFS_ERR_CORRUPT;
        }

        // skip padding
        off = vznncv_lfs_min(end - noff, 0x3fe) + noff;
        if (off < end) {
            off = vznncv_lfs_min(off, end - 2*sizeof(uint32_t));
        }
        noff = off + sizeof(uint32_t);
    }

    return 0;
}

static int vznncv_lfs_dir_alloc(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_mdir_t *dir) {
    // allocate pair of dir blocks (backwards, so we write block 1 first)
    for (int i = 0; i < 2; i++) {
        int err = vznncv_lfs_alloc(vznncv_lfs, &dir->pair[(i+1)%2]);
        if (err) {
            return err;
        }
    }

    // zero for reproducability in case initial block is unreadable
    dir->rev = 0;

    // rather than clobbering one of the blocks we just pretend
    // the revision may be valid
    int err = vznncv_lfs_bd_read(vznncv_lfs,
            NULL, &vznncv_lfs->rcache, sizeof(dir->rev),
            dir->pair[0], 0, &dir->rev, sizeof(dir->rev));
    dir->rev = vznncv_lfs_fromle32(dir->rev);
    if (err && err != VZNNCV_LFS_ERR_CORRUPT) {
        return err;
    }

    // make sure we don't immediately evict
    dir->rev += dir->rev & 1;

    // set defaults
    dir->off = sizeof(dir->rev);
    dir->etag = 0xffffffff;
    dir->count = 0;
#ifdef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_COMMIT_COMPACT_THRESHOLD
    dir->commit_count = 0;
#endif
    dir->tail[0] = VZNNCV_LFS_BLOCK_NULL;
    dir->tail[1] = VZNNCV_LFS_BLOCK_NULL;
    dir->erased = false;
    dir->split = false;

    // don't write out yet, let caller take care of that
    return 0;
}

static int vznncv_lfs_dir_drop(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_mdir_t *dir, vznncv_lfs_mdir_t *tail) {
    // steal state
    int err = vznncv_lfs_dir_getgstate(vznncv_lfs, tail, &vznncv_lfs->gdelta);
    if (err) {
        return err;
    }

    // steal tail
    vznncv_lfs_pair_tole32(tail->tail);
    err = vznncv_lfs_dir_commit(vznncv_lfs, dir, VZNNCV_LFS_MKATTRS(
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_TAIL + tail->split, 0x3ff, 8), tail->tail}));
    vznncv_lfs_pair_fromle32(tail->tail);
    if (err) {
        return err;
    }

    return 0;
}

static int vznncv_lfs_dir_split(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_mdir_t *dir, const struct vznncv_lfs_mattr *attrs, int attrcount,
        vznncv_lfs_mdir_t *source, uint16_t split, uint16_t end) {
    // create tail directory
    vznncv_lfs_alloc_ack(vznncv_lfs);
    vznncv_lfs_mdir_t tail;
    int err = vznncv_lfs_dir_alloc(vznncv_lfs, &tail);
    if (err) {
        return err;
    }

    tail.split = dir->split;
    tail.tail[0] = dir->tail[0];
    tail.tail[1] = dir->tail[1];

    err = vznncv_lfs_dir_compact(vznncv_lfs, &tail, attrs, attrcount, source, split, end);
    if (err) {
        return err;
    }

    dir->tail[0] = tail.pair[0];
    dir->tail[1] = tail.pair[1];
    dir->split = true;

    // update root if needed
    if (vznncv_lfs_pair_cmp(dir->pair, vznncv_lfs->root) == 0 && split == 0) {
        vznncv_lfs->root[0] = tail.pair[0];
        vznncv_lfs->root[1] = tail.pair[1];
    }

    return 0;
}

static int vznncv_lfs_dir_commit_size(void *p, vznncv_lfs_tag_t tag, const void *buffer) {
    vznncv_lfs_size_t *size = p;
    (void)buffer;

    *size += vznncv_lfs_tag_dsize(tag);
    return 0;
}

struct vznncv_lfs_dir_commit_commit {
    vznncv_lfs_t *vznncv_lfs;
    struct vznncv_lfs_commit *commit;
};

static int vznncv_lfs_dir_commit_commit(void *p, vznncv_lfs_tag_t tag, const void *buffer) {
    struct vznncv_lfs_dir_commit_commit *commit = p;
    return vznncv_lfs_dir_commitattr(commit->vznncv_lfs, commit->commit, tag, buffer);
}

static int vznncv_lfs_dir_compact(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_mdir_t *dir, const struct vznncv_lfs_mattr *attrs, int attrcount,
        vznncv_lfs_mdir_t *source, uint16_t begin, uint16_t end) {
    // save some state in case block is bad
    const vznncv_lfs_block_t oldpair[2] = {dir->pair[0], dir->pair[1]};
    bool relocated = false;
    bool tired = false;

    // should we split?
    while (end - begin > 1) {
        // find size
        vznncv_lfs_size_t size = 0;
        int err = vznncv_lfs_dir_traverse(vznncv_lfs,
                source, 0, 0xffffffff, attrs, attrcount,
                VZNNCV_LFS_MKTAG(0x400, 0x3ff, 0),
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_NAME, 0, 0),
                begin, end, -begin,
                vznncv_lfs_dir_commit_size, &size);
        if (err) {
            return err;
        }

        // space is complicated, we need room for tail, crc, gstate,
        // cleanup delete, and we cap at half a block to give room
        // for metadata updates.
        if (end - begin < 0xff &&
                size <= vznncv_lfs_min(vznncv_lfs->cfg->block_size - 36,
                    vznncv_lfs_alignup(vznncv_lfs->cfg->block_size/2,
                        vznncv_lfs->cfg->prog_size))) {
            break;
        }

        // can't fit, need to split, we should really be finding the
        // largest size that fits with a small binary search, but right now
        // it's not worth the code size
        uint16_t split = (end - begin) / 2;
        err = vznncv_lfs_dir_split(vznncv_lfs, dir, attrs, attrcount,
                source, begin+split, end);
        if (err) {
            // if we fail to split, we may be able to overcompact, unless
            // we're too big for even the full block, in which case our
            // only option is to error
            if (err == VZNNCV_LFS_ERR_NOSPC && size <= vznncv_lfs->cfg->block_size - 36) {
                break;
            }
            return err;
        }

        end = begin + split;
    }

    // increment revision count
    dir->rev += 1;
    // If our revision count == n * block_cycles, we should force a relocation,
    // this is how littlefs wear-levels at the metadata-pair level. Note that we
    // actually use (block_cycles+1)|1, this is to avoid two corner cases:
    // 1. block_cycles = 1, which would prevent relocations from terminating
    // 2. block_cycles = 2n, which, due to aliasing, would only ever relocate
    //    one metadata block in the pair, effectively making this useless
    if (vznncv_lfs->cfg->block_cycles > 0 &&
            (dir->rev % ((vznncv_lfs->cfg->block_cycles+1)|1) == 0)) {
        if (vznncv_lfs_pair_cmp(dir->pair, (const vznncv_lfs_block_t[2]){0, 1}) == 0) {
            // oh no! we're writing too much to the superblock,
            // should we expand?
            vznncv_lfs_ssize_t res = vznncv_lfs_fs_size(vznncv_lfs);
            if (res < 0) {
                return res;
            }

            // do we have extra space? littlefs can't reclaim this space
            // by itself, so expand cautiously
            if ((vznncv_lfs_size_t)res < vznncv_lfs->cfg->block_count/2) {
                VZNNCV_LFS_DEBUG("Expanding superblock at rev %"PRIu32, dir->rev);
                int err = vznncv_lfs_dir_split(vznncv_lfs, dir, attrs, attrcount,
                        source, begin, end);
                if (err && err != VZNNCV_LFS_ERR_NOSPC) {
                    return err;
                }

                // welp, we tried, if we ran out of space there's not much
                // we can do, we'll error later if we've become frozen
                if (!err) {
                    end = begin;
                }
            }
#ifdef VZNNCV_LFS_MIGRATE
        } else if (vznncv_lfs->vznncv_lfs1) {
            // do not proactively relocate blocks during migrations, this
            // can cause a number of failure states such: clobbering the
            // v1 superblock if we relocate root, and invalidating directory
            // pointers if we relocate the head of a directory. On top of
            // this, relocations increase the overall complexity of
            // vznncv_lfs_migration, which is already a delicate operation.
#endif
        } else {
            // we're writing too much, time to relocate
            tired = true;
            goto relocate;
        }
    }

    // begin loop to commit compaction to blocks until a compact sticks
    while (true) {
        {
            // setup commit state
            struct vznncv_lfs_commit commit = {
                .block = dir->pair[1],
                .off = 0,
                .ptag = 0xffffffff,
                .crc = 0xffffffff,

                .begin = 0,
                .end = vznncv_lfs->cfg->block_size - 8,
            };

            // erase block to write to
            int err = vznncv_lfs_bd_erase(vznncv_lfs, dir->pair[1]);
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // write out header
            dir->rev = vznncv_lfs_tole32(dir->rev);
            err = vznncv_lfs_dir_commitprog(vznncv_lfs, &commit,
                    &dir->rev, sizeof(dir->rev));
            dir->rev = vznncv_lfs_fromle32(dir->rev);
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // traverse the directory, this time writing out all unique tags
            err = vznncv_lfs_dir_traverse(vznncv_lfs,
                    source, 0, 0xffffffff, attrs, attrcount,
                    VZNNCV_LFS_MKTAG(0x400, 0x3ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_NAME, 0, 0),
                    begin, end, -begin,
                    vznncv_lfs_dir_commit_commit, &(struct vznncv_lfs_dir_commit_commit){
                        vznncv_lfs, &commit});
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // commit tail, which may be new after last size check
            if (!vznncv_lfs_pair_isnull(dir->tail)) {
                vznncv_lfs_pair_tole32(dir->tail);
                err = vznncv_lfs_dir_commitattr(vznncv_lfs, &commit,
                        VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_TAIL + dir->split, 0x3ff, 8),
                        dir->tail);
                vznncv_lfs_pair_fromle32(dir->tail);
                if (err) {
                    if (err == VZNNCV_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }

            // bring over gstate?
            vznncv_lfs_gstate_t delta = {0};
            if (!relocated) {
                vznncv_lfs_gstate_xor(&delta, &vznncv_lfs->gdisk);
                vznncv_lfs_gstate_xor(&delta, &vznncv_lfs->gstate);
            }
            vznncv_lfs_gstate_xor(&delta, &vznncv_lfs->gdelta);
            delta.tag &= ~VZNNCV_LFS_MKTAG(0, 0, 0x3ff);

            err = vznncv_lfs_dir_getgstate(vznncv_lfs, dir, &delta);
            if (err) {
                return err;
            }

            if (!vznncv_lfs_gstate_iszero(&delta)) {
                vznncv_lfs_gstate_tole32(&delta);
                err = vznncv_lfs_dir_commitattr(vznncv_lfs, &commit,
                        VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_MOVESTATE, 0x3ff,
                            sizeof(delta)), &delta);
                if (err) {
                    if (err == VZNNCV_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }

            // complete commit with crc
            err = vznncv_lfs_dir_commitcrc(vznncv_lfs, &commit);
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // successful compaction, swap dir pair to indicate most recent
            VZNNCV_LFS_ASSERT(commit.off % vznncv_lfs->cfg->prog_size == 0);
            vznncv_lfs_pair_swap(dir->pair);
            dir->count = end - begin;
            dir->off = commit.off;
            dir->etag = commit.ptag;
#ifdef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_COMMIT_COMPACT_THRESHOLD
            dir->commit_count = 1;
#endif
            // update gstate
            vznncv_lfs->gdelta = (vznncv_lfs_gstate_t){0};
            if (!relocated) {
                vznncv_lfs->gdisk = vznncv_lfs->gstate;
            }
        }
        break;

relocate:
        // commit was corrupted, drop caches and prepare to relocate block
        relocated = true;
        vznncv_lfs_cache_drop(vznncv_lfs, &vznncv_lfs->pcache);
        if (!tired) {
            VZNNCV_LFS_DEBUG("Bad block at 0x%"PRIx32, dir->pair[1]);
        }

        // can't relocate superblock, filesystem is now frozen
        if (vznncv_lfs_pair_cmp(dir->pair, (const vznncv_lfs_block_t[2]){0, 1}) == 0) {
            VZNNCV_LFS_WARN("Superblock 0x%"PRIx32" has become unwritable",
                    dir->pair[1]);
            return VZNNCV_LFS_ERR_NOSPC;
        }

        // relocate half of pair
        int err = vznncv_lfs_alloc(vznncv_lfs, &dir->pair[1]);
        if (err && (err != VZNNCV_LFS_ERR_NOSPC || !tired)) {
            return err;
        }

        tired = false;
        continue;
    }

    if (relocated) {
        // update references if we relocated
        VZNNCV_LFS_DEBUG("Relocating {0x%"PRIx32", 0x%"PRIx32"} "
                    "-> {0x%"PRIx32", 0x%"PRIx32"}",
                oldpair[0], oldpair[1], dir->pair[0], dir->pair[1]);
        int err = vznncv_lfs_fs_relocate(vznncv_lfs, oldpair, dir->pair);
        if (err) {
            return err;
        }
    }

    return 0;
}

static int vznncv_lfs_dir_commit(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_mdir_t *dir,
        const struct vznncv_lfs_mattr *attrs, int attrcount) {
    // check for any inline files that aren't RAM backed and
    // forcefully evict them, needed for filesystem consistency
    for (vznncv_lfs_file_t *f = (vznncv_lfs_file_t*)vznncv_lfs->mlist; f; f = f->next) {
        if (dir != &f->m && vznncv_lfs_pair_cmp(f->m.pair, dir->pair) == 0 &&
                f->type == VZNNCV_LFS_TYPE_REG && (f->flags & VZNNCV_LFS_F_INLINE) &&
                f->ctz.size > vznncv_lfs->cfg->cache_size) {
            int err = vznncv_lfs_file_outline(vznncv_lfs, f);
            if (err) {
                return err;
            }

            err = vznncv_lfs_file_flush(vznncv_lfs, f);
            if (err) {
                return err;
            }
        }
    }

    // calculate changes to the directory
    vznncv_lfs_mdir_t olddir = *dir;
    bool hasdelete = false;
    for (int i = 0; i < attrcount; i++) {
        if (vznncv_lfs_tag_type3(attrs[i].tag) == VZNNCV_LFS_TYPE_CREATE) {
            dir->count += 1;
        } else if (vznncv_lfs_tag_type3(attrs[i].tag) == VZNNCV_LFS_TYPE_DELETE) {
            VZNNCV_LFS_ASSERT(dir->count > 0);
            dir->count -= 1;
            hasdelete = true;
        } else if (vznncv_lfs_tag_type1(attrs[i].tag) == VZNNCV_LFS_TYPE_TAIL) {
            dir->tail[0] = ((vznncv_lfs_block_t*)attrs[i].buffer)[0];
            dir->tail[1] = ((vznncv_lfs_block_t*)attrs[i].buffer)[1];
            dir->split = (vznncv_lfs_tag_chunk(attrs[i].tag) & 1);
            vznncv_lfs_pair_fromle32(dir->tail);
        }
    }

    // should we actually drop the directory block?
    if (hasdelete && dir->count == 0) {
        vznncv_lfs_mdir_t pdir;
        int err = vznncv_lfs_fs_pred(vznncv_lfs, dir->pair, &pdir);
        if (err && err != VZNNCV_LFS_ERR_NOENT) {
            *dir = olddir;
            return err;
        }

        if (err != VZNNCV_LFS_ERR_NOENT && pdir.split) {
            err = vznncv_lfs_dir_drop(vznncv_lfs, &pdir, dir);
            if (err) {
                *dir = olddir;
                return err;
            }
        }
    }

    if (dir->erased || dir->count >= 0xff) {
#ifdef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_COMMIT_COMPACT_THRESHOLD
        if (vznncv_lfs->cfg->commit_compact_threshold && dir->commit_count >= vznncv_lfs->cfg->commit_compact_threshold) {
            goto compact;
        }
#endif
        // try to commit
        struct vznncv_lfs_commit commit = {
            .block = dir->pair[0],
            .off = dir->off,
            .ptag = dir->etag,
            .crc = 0xffffffff,

            .begin = dir->off,
            .end = vznncv_lfs->cfg->block_size - 8,
        };

        // traverse attrs that need to be written out
        vznncv_lfs_pair_tole32(dir->tail);
        int err = vznncv_lfs_dir_traverse(vznncv_lfs,
                dir, dir->off, dir->etag, attrs, attrcount,
                0, 0, 0, 0, 0,
                vznncv_lfs_dir_commit_commit, &(struct vznncv_lfs_dir_commit_commit){
                    vznncv_lfs, &commit});
        vznncv_lfs_pair_fromle32(dir->tail);
        if (err) {
            if (err == VZNNCV_LFS_ERR_NOSPC || err == VZNNCV_LFS_ERR_CORRUPT) {
                goto compact;
            }
            *dir = olddir;
            return err;
        }

        // commit any global diffs if we have any
        vznncv_lfs_gstate_t delta = {0};
        vznncv_lfs_gstate_xor(&delta, &vznncv_lfs->gstate);
        vznncv_lfs_gstate_xor(&delta, &vznncv_lfs->gdisk);
        vznncv_lfs_gstate_xor(&delta, &vznncv_lfs->gdelta);
        delta.tag &= ~VZNNCV_LFS_MKTAG(0, 0, 0x3ff);
        if (!vznncv_lfs_gstate_iszero(&delta)) {
            err = vznncv_lfs_dir_getgstate(vznncv_lfs, dir, &delta);
            if (err) {
                *dir = olddir;
                return err;
            }

            vznncv_lfs_gstate_tole32(&delta);
            err = vznncv_lfs_dir_commitattr(vznncv_lfs, &commit,
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_MOVESTATE, 0x3ff,
                        sizeof(delta)), &delta);
            if (err) {
                if (err == VZNNCV_LFS_ERR_NOSPC || err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto compact;
                }
                *dir = olddir;
                return err;
            }
        }

        // finalize commit with the crc
        err = vznncv_lfs_dir_commitcrc(vznncv_lfs, &commit);
        if (err) {
            if (err == VZNNCV_LFS_ERR_NOSPC || err == VZNNCV_LFS_ERR_CORRUPT) {
                goto compact;
            }
            *dir = olddir;
            return err;
        }

        // successful commit, update dir
        VZNNCV_LFS_ASSERT(commit.off % vznncv_lfs->cfg->prog_size == 0);
        dir->off = commit.off;
        dir->etag = commit.ptag;
#ifdef MBED_CONF_VZNNCV_MBED_LITTELFS_ENABLE_COMMIT_COMPACT_THRESHOLD
        dir->commit_count += 1;
#endif
        // and update gstate
        vznncv_lfs->gdisk = vznncv_lfs->gstate;
        vznncv_lfs->gdelta = (vznncv_lfs_gstate_t){0};
    } else {
compact:
        // fall back to compaction
        vznncv_lfs_cache_drop(vznncv_lfs, &vznncv_lfs->pcache);

        int err = vznncv_lfs_dir_compact(vznncv_lfs, dir, attrs, attrcount,
                dir, 0, dir->count);
        if (err) {
            *dir = olddir;
            return err;
        }
    }

    // this complicated bit of logic is for fixing up any active
    // metadata-pairs that we may have affected
    //
    // note we have to make two passes since the mdir passed to
    // vznncv_lfs_dir_commit could also be in this list, and even then
    // we need to copy the pair so they don't get clobbered if we refetch
    // our mdir.
    for (struct vznncv_lfs_mlist *d = vznncv_lfs->mlist; d; d = d->next) {
        if (&d->m != dir && vznncv_lfs_pair_cmp(d->m.pair, olddir.pair) == 0) {
            d->m = *dir;
            for (int i = 0; i < attrcount; i++) {
                if (vznncv_lfs_tag_type3(attrs[i].tag) == VZNNCV_LFS_TYPE_DELETE &&
                        d->id == vznncv_lfs_tag_id(attrs[i].tag)) {
                    d->m.pair[0] = VZNNCV_LFS_BLOCK_NULL;
                    d->m.pair[1] = VZNNCV_LFS_BLOCK_NULL;
                } else if (vznncv_lfs_tag_type3(attrs[i].tag) == VZNNCV_LFS_TYPE_DELETE &&
                        d->id > vznncv_lfs_tag_id(attrs[i].tag)) {
                    d->id -= 1;
                    if (d->type == VZNNCV_LFS_TYPE_DIR) {
                        ((vznncv_lfs_dir_t*)d)->pos -= 1;
                    }
                } else if (vznncv_lfs_tag_type3(attrs[i].tag) == VZNNCV_LFS_TYPE_CREATE &&
                        d->id >= vznncv_lfs_tag_id(attrs[i].tag)) {
                    d->id += 1;
                    if (d->type == VZNNCV_LFS_TYPE_DIR) {
                        ((vznncv_lfs_dir_t*)d)->pos += 1;
                    }
                }
            }
        }
    }

    for (struct vznncv_lfs_mlist *d = vznncv_lfs->mlist; d; d = d->next) {
        if (vznncv_lfs_pair_cmp(d->m.pair, olddir.pair) == 0) {
            while (d->id >= d->m.count && d->m.split) {
                // we split and id is on tail now
                d->id -= d->m.count;
                int err = vznncv_lfs_dir_fetch(vznncv_lfs, &d->m, d->m.tail);
                if (err) {
                    return err;
                }
            }
        }
    }

    return 0;
}


/// Top level directory operations ///
int vznncv_lfs_mkdir(vznncv_lfs_t *vznncv_lfs, const char *path) {
    VZNNCV_LFS_TRACE("vznncv_lfs_mkdir(%p, \"%s\")", (void*)vznncv_lfs, path);
    // deorphan if we haven't yet, needed at most once after poweron
    int err = vznncv_lfs_fs_forceconsistency(vznncv_lfs);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", err);
        return err;
    }

    struct vznncv_lfs_mlist cwd;
    cwd.next = vznncv_lfs->mlist;
    uint16_t id;
    err = vznncv_lfs_dir_find(vznncv_lfs, &cwd.m, &path, &id);
    if (!(err == VZNNCV_LFS_ERR_NOENT && id != 0x3ff)) {
        VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", (err < 0) ? err : VZNNCV_LFS_ERR_EXIST);
        return (err < 0) ? err : VZNNCV_LFS_ERR_EXIST;
    }

    // check that name fits
    vznncv_lfs_size_t nlen = strlen(path);
    if (nlen > vznncv_lfs->name_max) {
        VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", VZNNCV_LFS_ERR_NAMETOOLONG);
        return VZNNCV_LFS_ERR_NAMETOOLONG;
    }

    // build up new directory
    vznncv_lfs_alloc_ack(vznncv_lfs);
    vznncv_lfs_mdir_t dir;
    err = vznncv_lfs_dir_alloc(vznncv_lfs, &dir);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", err);
        return err;
    }

    // find end of list
    vznncv_lfs_mdir_t pred = cwd.m;
    while (pred.split) {
        err = vznncv_lfs_dir_fetch(vznncv_lfs, &pred, pred.tail);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", err);
            return err;
        }
    }

    // setup dir
    vznncv_lfs_pair_tole32(pred.tail);
    err = vznncv_lfs_dir_commit(vznncv_lfs, &dir, VZNNCV_LFS_MKATTRS(
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_SOFTTAIL, 0x3ff, 8), pred.tail}));
    vznncv_lfs_pair_fromle32(pred.tail);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", err);
        return err;
    }

    // current block end of list?
    if (cwd.m.split) {
        // update tails, this creates a desync
        vznncv_lfs_fs_preporphans(vznncv_lfs, +1);

        // it's possible our predecessor has to be relocated, and if
        // our parent is our predecessor's predecessor, this could have
        // caused our parent to go out of date, fortunately we can hook
        // ourselves into littlefs to catch this
        cwd.type = 0;
        cwd.id = 0;
        vznncv_lfs->mlist = &cwd;

        vznncv_lfs_pair_tole32(dir.pair);
        err = vznncv_lfs_dir_commit(vznncv_lfs, &pred, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
        vznncv_lfs_pair_fromle32(dir.pair);
        if (err) {
            vznncv_lfs->mlist = cwd.next;
            VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", err);
            return err;
        }

        vznncv_lfs->mlist = cwd.next;
        vznncv_lfs_fs_preporphans(vznncv_lfs, -1);
    }

    // now insert into our parent block
    vznncv_lfs_pair_tole32(dir.pair);
    err = vznncv_lfs_dir_commit(vznncv_lfs, &cwd.m, VZNNCV_LFS_MKATTRS(
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CREATE, id, 0), NULL},
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DIR, id, nlen), path},
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DIRSTRUCT, id, 8), dir.pair},
            {VZNNCV_LFS_MKTAG_IF(!cwd.m.split,
                VZNNCV_LFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
    vznncv_lfs_pair_fromle32(dir.pair);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", err);
        return err;
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_mkdir -> %d", 0);
    return 0;
}

int vznncv_lfs_dir_open(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_dir_t *dir, const char *path) {
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_open(%p, %p, \"%s\")", (void*)vznncv_lfs, (void*)dir, path);
    vznncv_lfs_stag_t tag = vznncv_lfs_dir_find(vznncv_lfs, &dir->m, &path, NULL);
    if (tag < 0) {
        VZNNCV_LFS_TRACE("vznncv_lfs_dir_open -> %"PRId32, tag);
        return tag;
    }

    if (vznncv_lfs_tag_type3(tag) != VZNNCV_LFS_TYPE_DIR) {
        VZNNCV_LFS_TRACE("vznncv_lfs_dir_open -> %d", VZNNCV_LFS_ERR_NOTDIR);
        return VZNNCV_LFS_ERR_NOTDIR;
    }

    vznncv_lfs_block_t pair[2];
    if (vznncv_lfs_tag_id(tag) == 0x3ff) {
        // handle root dir separately
        pair[0] = vznncv_lfs->root[0];
        pair[1] = vznncv_lfs->root[1];
    } else {
        // get dir pair from parent
        vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, &dir->m, VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, vznncv_lfs_tag_id(tag), 8), pair);
        if (res < 0) {
            VZNNCV_LFS_TRACE("vznncv_lfs_dir_open -> %"PRId32, res);
            return res;
        }
        vznncv_lfs_pair_fromle32(pair);
    }

    // fetch first pair
    int err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir->m, pair);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_dir_open -> %d", err);
        return err;
    }

    // setup entry
    dir->head[0] = dir->m.pair[0];
    dir->head[1] = dir->m.pair[1];
    dir->id = 0;
    dir->pos = 0;

    // add to list of mdirs
    dir->type = VZNNCV_LFS_TYPE_DIR;
    dir->next = (vznncv_lfs_dir_t*)vznncv_lfs->mlist;
    vznncv_lfs->mlist = (struct vznncv_lfs_mlist*)dir;

    VZNNCV_LFS_TRACE("vznncv_lfs_dir_open -> %d", 0);
    return 0;
}

int vznncv_lfs_dir_close(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_dir_t *dir) {
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_close(%p, %p)", (void*)vznncv_lfs, (void*)dir);
    // remove from list of mdirs
    for (struct vznncv_lfs_mlist **p = &vznncv_lfs->mlist; *p; p = &(*p)->next) {
        if (*p == (struct vznncv_lfs_mlist*)dir) {
            *p = (*p)->next;
            break;
        }
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_dir_close -> %d", 0);
    return 0;
}

int vznncv_lfs_dir_read(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_dir_t *dir, struct vznncv_lfs_info *info) {
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_read(%p, %p, %p)",
            (void*)vznncv_lfs, (void*)dir, (void*)info);
    memset(info, 0, sizeof(*info));

    // special offset for '.' and '..'
    if (dir->pos == 0) {
        info->type = VZNNCV_LFS_TYPE_DIR;
        strcpy(info->name, ".");
        dir->pos += 1;
        VZNNCV_LFS_TRACE("vznncv_lfs_dir_read -> %d", true);
        return true;
    } else if (dir->pos == 1) {
        info->type = VZNNCV_LFS_TYPE_DIR;
        strcpy(info->name, "..");
        dir->pos += 1;
        VZNNCV_LFS_TRACE("vznncv_lfs_dir_read -> %d", true);
        return true;
    }

    while (true) {
        if (dir->id == dir->m.count) {
            if (!dir->m.split) {
                VZNNCV_LFS_TRACE("vznncv_lfs_dir_read -> %d", false);
                return false;
            }

            int err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir->m, dir->m.tail);
            if (err) {
                VZNNCV_LFS_TRACE("vznncv_lfs_dir_read -> %d", err);
                return err;
            }

            dir->id = 0;
        }

        int err = vznncv_lfs_dir_getinfo(vznncv_lfs, &dir->m, dir->id, info);
        if (err && err != VZNNCV_LFS_ERR_NOENT) {
            VZNNCV_LFS_TRACE("vznncv_lfs_dir_read -> %d", err);
            return err;
        }

        dir->id += 1;
        if (err != VZNNCV_LFS_ERR_NOENT) {
            break;
        }
    }

    dir->pos += 1;
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_read -> %d", true);
    return true;
}

int vznncv_lfs_dir_seek(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_dir_t *dir, vznncv_lfs_off_t off) {
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_seek(%p, %p, %"PRIu32")",
            (void*)vznncv_lfs, (void*)dir, off);
    // simply walk from head dir
    int err = vznncv_lfs_dir_rewind(vznncv_lfs, dir);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_dir_seek -> %d", err);
        return err;
    }

    // first two for ./..
    dir->pos = vznncv_lfs_min(2, off);
    off -= dir->pos;

    // skip superblock entry
    dir->id = (off > 0 && vznncv_lfs_pair_cmp(dir->head, vznncv_lfs->root) == 0);

    while (off > 0) {
        int diff = vznncv_lfs_min(dir->m.count - dir->id, off);
        dir->id += diff;
        dir->pos += diff;
        off -= diff;

        if (dir->id == dir->m.count) {
            if (!dir->m.split) {
                VZNNCV_LFS_TRACE("vznncv_lfs_dir_seek -> %d", VZNNCV_LFS_ERR_INVAL);
                return VZNNCV_LFS_ERR_INVAL;
            }

            err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir->m, dir->m.tail);
            if (err) {
                VZNNCV_LFS_TRACE("vznncv_lfs_dir_seek -> %d", err);
                return err;
            }

            dir->id = 0;
        }
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_dir_seek -> %d", 0);
    return 0;
}

vznncv_lfs_soff_t vznncv_lfs_dir_tell(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_dir_t *dir) {
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_tell(%p, %p)", (void*)vznncv_lfs, (void*)dir);
    (void)vznncv_lfs;
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_tell -> %"PRId32, dir->pos);
    return dir->pos;
}

int vznncv_lfs_dir_rewind(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_dir_t *dir) {
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_rewind(%p, %p)", (void*)vznncv_lfs, (void*)dir);
    // reload the head dir
    int err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir->m, dir->head);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_dir_rewind -> %d", err);
        return err;
    }

    dir->id = 0;
    dir->pos = 0;
    VZNNCV_LFS_TRACE("vznncv_lfs_dir_rewind -> %d", 0);
    return 0;
}


/// File index list operations ///
static int vznncv_lfs_ctz_index(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_off_t *off) {
    vznncv_lfs_off_t size = *off;
    vznncv_lfs_off_t b = vznncv_lfs->cfg->block_size - 2*4;
    vznncv_lfs_off_t i = size / b;
    if (i == 0) {
        return 0;
    }

    i = (size - 4*(vznncv_lfs_popc(i-1)+2)) / b;
    *off = size - b*i - 4*vznncv_lfs_popc(i);
    return i;
}

static int vznncv_lfs_ctz_find(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache,
        vznncv_lfs_block_t head, vznncv_lfs_size_t size,
        vznncv_lfs_size_t pos, vznncv_lfs_block_t *block, vznncv_lfs_off_t *off) {
    if (size == 0) {
        *block = VZNNCV_LFS_BLOCK_NULL;
        *off = 0;
        return 0;
    }

    vznncv_lfs_off_t current = vznncv_lfs_ctz_index(vznncv_lfs, &(vznncv_lfs_off_t){size-1});
    vznncv_lfs_off_t target = vznncv_lfs_ctz_index(vznncv_lfs, &pos);

    while (current > target) {
        vznncv_lfs_size_t skip = vznncv_lfs_min(
                vznncv_lfs_npw2(current-target+1) - 1,
                vznncv_lfs_ctz(current));

        int err = vznncv_lfs_bd_read(vznncv_lfs,
                pcache, rcache, sizeof(head),
                head, 4*skip, &head, sizeof(head));
        head = vznncv_lfs_fromle32(head);
        if (err) {
            return err;
        }

        current -= 1 << skip;
    }

    *block = head;
    *off = pos;
    return 0;
}

static int vznncv_lfs_ctz_extend(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache,
        vznncv_lfs_block_t head, vznncv_lfs_size_t size,
        vznncv_lfs_block_t *block, vznncv_lfs_off_t *off) {
    while (true) {
        // go ahead and grab a block
        vznncv_lfs_block_t nblock;
        int err = vznncv_lfs_alloc(vznncv_lfs, &nblock);
        if (err) {
            return err;
        }

        {
            err = vznncv_lfs_bd_erase(vznncv_lfs, nblock);
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            if (size == 0) {
                *block = nblock;
                *off = 0;
                return 0;
            }

            vznncv_lfs_size_t noff = size - 1;
            vznncv_lfs_off_t index = vznncv_lfs_ctz_index(vznncv_lfs, &noff);
            noff = noff + 1;

            // just copy out the last block if it is incomplete
            if (noff != vznncv_lfs->cfg->block_size) {
                for (vznncv_lfs_off_t i = 0; i < noff; i++) {
                    uint8_t data;
                    err = vznncv_lfs_bd_read(vznncv_lfs,
                            NULL, rcache, noff-i,
                            head, i, &data, 1);
                    if (err) {
                        return err;
                    }

                    err = vznncv_lfs_bd_prog(vznncv_lfs,
                            pcache, rcache, true,
                            nblock, i, &data, 1);
                    if (err) {
                        if (err == VZNNCV_LFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }
                }

                *block = nblock;
                *off = noff;
                return 0;
            }

            // append block
            index += 1;
            vznncv_lfs_size_t skips = vznncv_lfs_ctz(index) + 1;
            vznncv_lfs_block_t nhead = head;
            for (vznncv_lfs_off_t i = 0; i < skips; i++) {
                nhead = vznncv_lfs_tole32(nhead);
                err = vznncv_lfs_bd_prog(vznncv_lfs, pcache, rcache, true,
                        nblock, 4*i, &nhead, 4);
                nhead = vznncv_lfs_fromle32(nhead);
                if (err) {
                    if (err == VZNNCV_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                if (i != skips-1) {
                    err = vznncv_lfs_bd_read(vznncv_lfs,
                            NULL, rcache, sizeof(nhead),
                            nhead, 4*i, &nhead, sizeof(nhead));
                    nhead = vznncv_lfs_fromle32(nhead);
                    if (err) {
                        return err;
                    }
                }
            }

            *block = nblock;
            *off = 4*skips;
            return 0;
        }

relocate:
        VZNNCV_LFS_DEBUG("Bad block at 0x%"PRIx32, nblock);

        // just clear cache and try a new block
        vznncv_lfs_cache_drop(vznncv_lfs, pcache);
    }
}

static int vznncv_lfs_ctz_traverse(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_cache_t *pcache, vznncv_lfs_cache_t *rcache,
        vznncv_lfs_block_t head, vznncv_lfs_size_t size,
        int (*cb)(void*, vznncv_lfs_block_t), void *data) {
    if (size == 0) {
        return 0;
    }

    vznncv_lfs_off_t index = vznncv_lfs_ctz_index(vznncv_lfs, &(vznncv_lfs_off_t){size-1});

    while (true) {
        int err = cb(data, head);
        if (err) {
            return err;
        }

        if (index == 0) {
            return 0;
        }

        vznncv_lfs_block_t heads[2];
        int count = 2 - (index & 1);
        err = vznncv_lfs_bd_read(vznncv_lfs,
                pcache, rcache, count*sizeof(head),
                head, 0, &heads, count*sizeof(head));
        heads[0] = vznncv_lfs_fromle32(heads[0]);
        heads[1] = vznncv_lfs_fromle32(heads[1]);
        if (err) {
            return err;
        }

        for (int i = 0; i < count-1; i++) {
            err = cb(data, heads[i]);
            if (err) {
                return err;
            }
        }

        head = heads[count-1];
        index -= count;
    }
}


/// Top level file operations ///
int vznncv_lfs_file_opencfg(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file,
        const char *path, int flags,
        const struct vznncv_lfs_file_config *cfg) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_opencfg(%p, %p, \"%s\", %x, %p {"
                 ".buffer=%p, .attrs=%p, .attr_count=%"PRIu32"})",
            (void*)vznncv_lfs, (void*)file, path, flags,
            (void*)cfg, cfg->buffer, (void*)cfg->attrs, cfg->attr_count);

    // deorphan if we haven't yet, needed at most once after poweron
    if ((flags & 3) != VZNNCV_LFS_O_RDONLY) {
        int err = vznncv_lfs_fs_forceconsistency(vznncv_lfs);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_file_opencfg -> %d", err);
            return err;
        }
    }

    // setup simple file details
    int err;
    file->cfg = cfg;
    file->flags = flags | VZNNCV_LFS_F_OPENED;
    file->pos = 0;
    file->off = 0;
    file->cache.buffer = NULL;

    // allocate entry for file if it doesn't exist
    vznncv_lfs_stag_t tag = vznncv_lfs_dir_find(vznncv_lfs, &file->m, &path, &file->id);
    if (tag < 0 && !(tag == VZNNCV_LFS_ERR_NOENT && file->id != 0x3ff)) {
        err = tag;
        goto cleanup;
    }

    // get id, add to list of mdirs to catch update changes
    file->type = VZNNCV_LFS_TYPE_REG;
    file->next = (vznncv_lfs_file_t*)vznncv_lfs->mlist;
    vznncv_lfs->mlist = (struct vznncv_lfs_mlist*)file;

    if (tag == VZNNCV_LFS_ERR_NOENT) {
        if (!(flags & VZNNCV_LFS_O_CREAT)) {
            err = VZNNCV_LFS_ERR_NOENT;
            goto cleanup;
        }

        // check that name fits
        vznncv_lfs_size_t nlen = strlen(path);
        if (nlen > vznncv_lfs->name_max) {
            err = VZNNCV_LFS_ERR_NAMETOOLONG;
            goto cleanup;
        }

        // get next slot and create entry to remember name
        err = vznncv_lfs_dir_commit(vznncv_lfs, &file->m, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CREATE, file->id, 0), NULL},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_REG, file->id, nlen), path},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, file->id, 0), NULL}));
        if (err) {
            err = VZNNCV_LFS_ERR_NAMETOOLONG;
            goto cleanup;
        }

        tag = VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, 0, 0);
    } else if (flags & VZNNCV_LFS_O_EXCL) {
        err = VZNNCV_LFS_ERR_EXIST;
        goto cleanup;
    } else if (vznncv_lfs_tag_type3(tag) != VZNNCV_LFS_TYPE_REG) {
        err = VZNNCV_LFS_ERR_ISDIR;
        goto cleanup;
    } else if (flags & VZNNCV_LFS_O_TRUNC) {
        // truncate if requested
        tag = VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, file->id, 0);
        file->flags |= VZNNCV_LFS_F_DIRTY;
    } else {
        // try to load what's on disk, if it's inlined we'll fix it later
        tag = vznncv_lfs_dir_get(vznncv_lfs, &file->m, VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, file->id, 8), &file->ctz);
        if (tag < 0) {
            err = tag;
            goto cleanup;
        }
        vznncv_lfs_ctz_fromle32(&file->ctz);
    }

    // fetch attrs
    for (unsigned i = 0; i < file->cfg->attr_count; i++) {
        if ((file->flags & 3) != VZNNCV_LFS_O_WRONLY) {
            vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, &file->m,
                    VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_USERATTR + file->cfg->attrs[i].type,
                        file->id, file->cfg->attrs[i].size),
                        file->cfg->attrs[i].buffer);
            if (res < 0 && res != VZNNCV_LFS_ERR_NOENT) {
                err = res;
                goto cleanup;
            }
        }

        if ((file->flags & 3) != VZNNCV_LFS_O_RDONLY) {
            if (file->cfg->attrs[i].size > vznncv_lfs->attr_max) {
                err = VZNNCV_LFS_ERR_NOSPC;
                goto cleanup;
            }

            file->flags |= VZNNCV_LFS_F_DIRTY;
        }
    }

    // allocate buffer if needed
    if (file->cfg->buffer) {
        file->cache.buffer = file->cfg->buffer;
    } else {
        file->cache.buffer = vznncv_lfs_malloc(vznncv_lfs->cfg->cache_size);
        if (!file->cache.buffer) {
            err = VZNNCV_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // zero to avoid information leak
    vznncv_lfs_cache_zero(vznncv_lfs, &file->cache);

    if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_TYPE_INLINESTRUCT) {
        // load inline files
        file->ctz.head = VZNNCV_LFS_BLOCK_INLINE;
        file->ctz.size = vznncv_lfs_tag_size(tag);
        file->flags |= VZNNCV_LFS_F_INLINE;
        file->cache.block = file->ctz.head;
        file->cache.off = 0;
        file->cache.size = vznncv_lfs->cfg->cache_size;

        // don't always read (may be new/trunc file)
        if (file->ctz.size > 0) {
            vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, &file->m,
                    VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, file->id,
                        vznncv_lfs_min(file->cache.size, 0x3fe)),
                    file->cache.buffer);
            if (res < 0) {
                err = res;
                goto cleanup;
            }
        }
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_file_opencfg -> %d", 0);
    return 0;

cleanup:
    // clean up lingering resources
    file->flags |= VZNNCV_LFS_F_ERRED;
    vznncv_lfs_file_close(vznncv_lfs, file);
    VZNNCV_LFS_TRACE("vznncv_lfs_file_opencfg -> %d", err);
    return err;
}

int vznncv_lfs_file_open(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file,
        const char *path, int flags) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_open(%p, %p, \"%s\", %x)",
            (void*)vznncv_lfs, (void*)file, path, flags);
    static const struct vznncv_lfs_file_config defaults = {0};
    int err = vznncv_lfs_file_opencfg(vznncv_lfs, file, path, flags, &defaults);
    VZNNCV_LFS_TRACE("vznncv_lfs_file_open -> %d", err);
    return err;
}

int vznncv_lfs_file_close(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_close(%p, %p)", (void*)vznncv_lfs, (void*)file);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);

    int err = vznncv_lfs_file_sync(vznncv_lfs, file);

    // remove from list of mdirs
    for (struct vznncv_lfs_mlist **p = &vznncv_lfs->mlist; *p; p = &(*p)->next) {
        if (*p == (struct vznncv_lfs_mlist*)file) {
            *p = (*p)->next;
            break;
        }
    }

    // clean up memory
    if (!file->cfg->buffer) {
        vznncv_lfs_free(file->cache.buffer);
    }

    file->flags &= ~VZNNCV_LFS_F_OPENED;
    VZNNCV_LFS_TRACE("vznncv_lfs_file_close -> %d", err);
    return err;
}

static int vznncv_lfs_file_relocate(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);

    while (true) {
        // just relocate what exists into new block
        vznncv_lfs_block_t nblock;
        int err = vznncv_lfs_alloc(vznncv_lfs, &nblock);
        if (err) {
            return err;
        }

        err = vznncv_lfs_bd_erase(vznncv_lfs, nblock);
        if (err) {
            if (err == VZNNCV_LFS_ERR_CORRUPT) {
                goto relocate;
            }
            return err;
        }

        // either read from dirty cache or disk
        for (vznncv_lfs_off_t i = 0; i < file->off; i++) {
            uint8_t data;
            if (file->flags & VZNNCV_LFS_F_INLINE) {
                err = vznncv_lfs_dir_getread(vznncv_lfs, &file->m,
                        // note we evict inline files before they can be dirty
                        NULL, &file->cache, file->off-i,
                        VZNNCV_LFS_MKTAG(0xfff, 0x1ff, 0),
                        VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, file->id, 0),
                        i, &data, 1);
                if (err) {
                    return err;
                }
            } else {
                err = vznncv_lfs_bd_read(vznncv_lfs,
                        &file->cache, &vznncv_lfs->rcache, file->off-i,
                        file->block, i, &data, 1);
                if (err) {
                    return err;
                }
            }

            err = vznncv_lfs_bd_prog(vznncv_lfs,
                    &vznncv_lfs->pcache, &vznncv_lfs->rcache, true,
                    nblock, i, &data, 1);
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }
        }

        // copy over new state of file
        memcpy(file->cache.buffer, vznncv_lfs->pcache.buffer, vznncv_lfs->cfg->cache_size);
        file->cache.block = vznncv_lfs->pcache.block;
        file->cache.off = vznncv_lfs->pcache.off;
        file->cache.size = vznncv_lfs->pcache.size;
        vznncv_lfs_cache_zero(vznncv_lfs, &vznncv_lfs->pcache);

        file->block = nblock;
        file->flags |= VZNNCV_LFS_F_WRITING;
        return 0;

relocate:
        VZNNCV_LFS_DEBUG("Bad block at 0x%"PRIx32, nblock);

        // just clear cache and try a new block
        vznncv_lfs_cache_drop(vznncv_lfs, &vznncv_lfs->pcache);
    }
}

static int vznncv_lfs_file_outline(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    file->off = file->pos;
    vznncv_lfs_alloc_ack(vznncv_lfs);
    int err = vznncv_lfs_file_relocate(vznncv_lfs, file);
    if (err) {
        return err;
    }

    file->flags &= ~VZNNCV_LFS_F_INLINE;
    return 0;
}

static int vznncv_lfs_file_flush(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);

    if (file->flags & VZNNCV_LFS_F_READING) {
        if (!(file->flags & VZNNCV_LFS_F_INLINE)) {
            vznncv_lfs_cache_drop(vznncv_lfs, &file->cache);
        }
        file->flags &= ~VZNNCV_LFS_F_READING;
    }

    if (file->flags & VZNNCV_LFS_F_WRITING) {
        vznncv_lfs_off_t pos = file->pos;

        if (!(file->flags & VZNNCV_LFS_F_INLINE)) {
            // copy over anything after current branch
            vznncv_lfs_file_t orig = {
                .ctz.head = file->ctz.head,
                .ctz.size = file->ctz.size,
                .flags = VZNNCV_LFS_O_RDONLY | VZNNCV_LFS_F_OPENED,
                .pos = file->pos,
                .cache = vznncv_lfs->rcache,
            };
            vznncv_lfs_cache_drop(vznncv_lfs, &vznncv_lfs->rcache);

            while (file->pos < file->ctz.size) {
                // copy over a byte at a time, leave it up to caching
                // to make this efficient
                uint8_t data;
                vznncv_lfs_ssize_t res = vznncv_lfs_file_read(vznncv_lfs, &orig, &data, 1);
                if (res < 0) {
                    return res;
                }

                res = vznncv_lfs_file_write(vznncv_lfs, file, &data, 1);
                if (res < 0) {
                    return res;
                }

                // keep our reference to the rcache in sync
                if (vznncv_lfs->rcache.block != VZNNCV_LFS_BLOCK_NULL) {
                    vznncv_lfs_cache_drop(vznncv_lfs, &orig.cache);
                    vznncv_lfs_cache_drop(vznncv_lfs, &vznncv_lfs->rcache);
                }
            }

            // write out what we have
            while (true) {
                int err = vznncv_lfs_bd_flush(vznncv_lfs, &file->cache, &vznncv_lfs->rcache, true);
                if (err) {
                    if (err == VZNNCV_LFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                break;

relocate:
                VZNNCV_LFS_DEBUG("Bad block at 0x%"PRIx32, file->block);
                err = vznncv_lfs_file_relocate(vznncv_lfs, file);
                if (err) {
                    return err;
                }
            }
        } else {
            file->pos = vznncv_lfs_max(file->pos, file->ctz.size);
        }

        // actual file updates
        file->ctz.head = file->block;
        file->ctz.size = file->pos;
        file->flags &= ~VZNNCV_LFS_F_WRITING;
        file->flags |= VZNNCV_LFS_F_DIRTY;

        file->pos = pos;
    }

    return 0;
}

int vznncv_lfs_file_sync(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_sync(%p, %p)", (void*)vznncv_lfs, (void*)file);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);

    if (file->flags & VZNNCV_LFS_F_ERRED) {
        // it's not safe to do anything if our file errored
        VZNNCV_LFS_TRACE("vznncv_lfs_file_sync -> %d", 0);
        return 0;
    }

    int err = vznncv_lfs_file_flush(vznncv_lfs, file);
    if (err) {
        file->flags |= VZNNCV_LFS_F_ERRED;
        VZNNCV_LFS_TRACE("vznncv_lfs_file_sync -> %d", err);
        return err;
    }

    if ((file->flags & VZNNCV_LFS_F_DIRTY) &&
            !vznncv_lfs_pair_isnull(file->m.pair)) {
        // update dir entry
        uint16_t type;
        const void *buffer;
        vznncv_lfs_size_t size;
        struct vznncv_lfs_ctz ctz;
        if (file->flags & VZNNCV_LFS_F_INLINE) {
            // inline the whole file
            type = VZNNCV_LFS_TYPE_INLINESTRUCT;
            buffer = file->cache.buffer;
            size = file->ctz.size;
        } else {
            // update the ctz reference
            type = VZNNCV_LFS_TYPE_CTZSTRUCT;
            // copy ctz so alloc will work during a relocate
            ctz = file->ctz;
            vznncv_lfs_ctz_tole32(&ctz);
            buffer = &ctz;
            size = sizeof(ctz);
        }

        // commit file data and attributes
        err = vznncv_lfs_dir_commit(vznncv_lfs, &file->m, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG(type, file->id, size), buffer},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_FROM_USERATTRS, file->id,
                    file->cfg->attr_count), file->cfg->attrs}));
        if (err) {
            file->flags |= VZNNCV_LFS_F_ERRED;
            VZNNCV_LFS_TRACE("vznncv_lfs_file_sync -> %d", err);
            return err;
        }

        file->flags &= ~VZNNCV_LFS_F_DIRTY;
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_file_sync -> %d", 0);
    return 0;
}

vznncv_lfs_ssize_t vznncv_lfs_file_read(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file,
        void *buffer, vznncv_lfs_size_t size) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_read(%p, %p, %p, %"PRIu32")",
            (void*)vznncv_lfs, (void*)file, buffer, size);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);
    VZNNCV_LFS_ASSERT((file->flags & 3) != VZNNCV_LFS_O_WRONLY);

    uint8_t *data = buffer;
    vznncv_lfs_size_t nsize = size;

    if (file->flags & VZNNCV_LFS_F_WRITING) {
        // flush out any writes
        int err = vznncv_lfs_file_flush(vznncv_lfs, file);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_file_read -> %d", err);
            return err;
        }
    }

    if (file->pos >= file->ctz.size) {
        // eof if past end
        VZNNCV_LFS_TRACE("vznncv_lfs_file_read -> %d", 0);
        return 0;
    }

    size = vznncv_lfs_min(size, file->ctz.size - file->pos);
    nsize = size;

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & VZNNCV_LFS_F_READING) ||
                file->off == vznncv_lfs->cfg->block_size) {
            if (!(file->flags & VZNNCV_LFS_F_INLINE)) {
                int err = vznncv_lfs_ctz_find(vznncv_lfs, NULL, &file->cache,
                        file->ctz.head, file->ctz.size,
                        file->pos, &file->block, &file->off);
                if (err) {
                    VZNNCV_LFS_TRACE("vznncv_lfs_file_read -> %d", err);
                    return err;
                }
            } else {
                file->block = VZNNCV_LFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= VZNNCV_LFS_F_READING;
        }

        // read as much as we can in current block
        vznncv_lfs_size_t diff = vznncv_lfs_min(nsize, vznncv_lfs->cfg->block_size - file->off);
        if (file->flags & VZNNCV_LFS_F_INLINE) {
            int err = vznncv_lfs_dir_getread(vznncv_lfs, &file->m,
                    NULL, &file->cache, vznncv_lfs->cfg->block_size,
                    VZNNCV_LFS_MKTAG(0xfff, 0x1ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, file->id, 0),
                    file->off, data, diff);
            if (err) {
                VZNNCV_LFS_TRACE("vznncv_lfs_file_read -> %d", err);
                return err;
            }
        } else {
            int err = vznncv_lfs_bd_read(vznncv_lfs,
                    NULL, &file->cache, vznncv_lfs->cfg->block_size,
                    file->block, file->off, data, diff);
            if (err) {
                VZNNCV_LFS_TRACE("vznncv_lfs_file_read -> %d", err);
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_file_read -> %"PRId32, size);
    return size;
}

vznncv_lfs_ssize_t vznncv_lfs_file_write(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file,
        const void *buffer, vznncv_lfs_size_t size) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_write(%p, %p, %p, %"PRIu32")",
            (void*)vznncv_lfs, (void*)file, buffer, size);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);
    VZNNCV_LFS_ASSERT((file->flags & 3) != VZNNCV_LFS_O_RDONLY);

    const uint8_t *data = buffer;
    vznncv_lfs_size_t nsize = size;

    if (file->flags & VZNNCV_LFS_F_READING) {
        // drop any reads
        int err = vznncv_lfs_file_flush(vznncv_lfs, file);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %d", err);
            return err;
        }
    }

    if ((file->flags & VZNNCV_LFS_O_APPEND) && file->pos < file->ctz.size) {
        file->pos = file->ctz.size;
    }

    if (file->pos + size > vznncv_lfs->file_max) {
        // Larger than file limit?
        VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %d", VZNNCV_LFS_ERR_FBIG);
        return VZNNCV_LFS_ERR_FBIG;
    }

    if (!(file->flags & VZNNCV_LFS_F_WRITING) && file->pos > file->ctz.size) {
        // fill with zeros
        vznncv_lfs_off_t pos = file->pos;
        file->pos = file->ctz.size;

        while (file->pos < pos) {
            vznncv_lfs_ssize_t res = vznncv_lfs_file_write(vznncv_lfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %"PRId32, res);
                return res;
            }
        }
    }

    if ((file->flags & VZNNCV_LFS_F_INLINE) &&
            vznncv_lfs_max(file->pos+nsize, file->ctz.size) >
            vznncv_lfs_min(0x3fe, vznncv_lfs_min(
                vznncv_lfs->cfg->cache_size, vznncv_lfs->cfg->block_size/8))) {
        // inline file doesn't fit anymore
        int err = vznncv_lfs_file_outline(vznncv_lfs, file);
        if (err) {
            file->flags |= VZNNCV_LFS_F_ERRED;
            VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %d", err);
            return err;
        }
    }

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & VZNNCV_LFS_F_WRITING) ||
                file->off == vznncv_lfs->cfg->block_size) {
            if (!(file->flags & VZNNCV_LFS_F_INLINE)) {
                if (!(file->flags & VZNNCV_LFS_F_WRITING) && file->pos > 0) {
                    // find out which block we're extending from
                    int err = vznncv_lfs_ctz_find(vznncv_lfs, NULL, &file->cache,
                            file->ctz.head, file->ctz.size,
                            file->pos-1, &file->block, &file->off);
                    if (err) {
                        file->flags |= VZNNCV_LFS_F_ERRED;
                        VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %d", err);
                        return err;
                    }

                    // mark cache as dirty since we may have read data into it
                    vznncv_lfs_cache_zero(vznncv_lfs, &file->cache);
                }

                // extend file with new blocks
                vznncv_lfs_alloc_ack(vznncv_lfs);
                int err = vznncv_lfs_ctz_extend(vznncv_lfs, &file->cache, &vznncv_lfs->rcache,
                        file->block, file->pos,
                        &file->block, &file->off);
                if (err) {
                    file->flags |= VZNNCV_LFS_F_ERRED;
                    VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %d", err);
                    return err;
                }
            } else {
                file->block = VZNNCV_LFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= VZNNCV_LFS_F_WRITING;
        }

        // program as much as we can in current block
        vznncv_lfs_size_t diff = vznncv_lfs_min(nsize, vznncv_lfs->cfg->block_size - file->off);
        while (true) {
            int err = vznncv_lfs_bd_prog(vznncv_lfs, &file->cache, &vznncv_lfs->rcache, true,
                    file->block, file->off, data, diff);
            if (err) {
                if (err == VZNNCV_LFS_ERR_CORRUPT) {
                    goto relocate;
                }
                file->flags |= VZNNCV_LFS_F_ERRED;
                VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %d", err);
                return err;
            }

            break;
relocate:
            err = vznncv_lfs_file_relocate(vznncv_lfs, file);
            if (err) {
                file->flags |= VZNNCV_LFS_F_ERRED;
                VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %d", err);
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;

        vznncv_lfs_alloc_ack(vznncv_lfs);
    }

    file->flags &= ~VZNNCV_LFS_F_ERRED;
    VZNNCV_LFS_TRACE("vznncv_lfs_file_write -> %"PRId32, size);
    return size;
}

vznncv_lfs_soff_t vznncv_lfs_file_seek(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file,
        vznncv_lfs_soff_t off, int whence) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_seek(%p, %p, %"PRId32", %d)",
            (void*)vznncv_lfs, (void*)file, off, whence);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);

    // write out everything beforehand, may be noop if rdonly
    int err = vznncv_lfs_file_flush(vznncv_lfs, file);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_file_seek -> %d", err);
        return err;
    }

    // find new pos
    vznncv_lfs_off_t npos = file->pos;
    if (whence == VZNNCV_LFS_SEEK_SET) {
        npos = off;
    } else if (whence == VZNNCV_LFS_SEEK_CUR) {
        npos = file->pos + off;
    } else if (whence == VZNNCV_LFS_SEEK_END) {
        npos = file->ctz.size + off;
    }

    if (npos > vznncv_lfs->file_max) {
        // file position out of range
        VZNNCV_LFS_TRACE("vznncv_lfs_file_seek -> %d", VZNNCV_LFS_ERR_INVAL);
        return VZNNCV_LFS_ERR_INVAL;
    }

    // update pos
    file->pos = npos;
    VZNNCV_LFS_TRACE("vznncv_lfs_file_seek -> %"PRId32, npos);
    return npos;
}

int vznncv_lfs_file_truncate(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file, vznncv_lfs_off_t size) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate(%p, %p, %"PRIu32")",
            (void*)vznncv_lfs, (void*)file, size);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);
    VZNNCV_LFS_ASSERT((file->flags & 3) != VZNNCV_LFS_O_RDONLY);

    if (size > VZNNCV_LFS_FILE_MAX) {
        VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate -> %d", VZNNCV_LFS_ERR_INVAL);
        return VZNNCV_LFS_ERR_INVAL;
    }

    vznncv_lfs_off_t pos = file->pos;
    vznncv_lfs_off_t oldsize = vznncv_lfs_file_size(vznncv_lfs, file);
    if (size < oldsize) {
        // need to flush since directly changing metadata
        int err = vznncv_lfs_file_flush(vznncv_lfs, file);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate -> %d", err);
            return err;
        }

        // lookup new head in ctz skip list
        err = vznncv_lfs_ctz_find(vznncv_lfs, NULL, &file->cache,
                file->ctz.head, file->ctz.size,
                size, &file->block, &file->off);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate -> %d", err);
            return err;
        }

        file->ctz.head = file->block;
        file->ctz.size = size;
        file->flags |= VZNNCV_LFS_F_DIRTY | VZNNCV_LFS_F_READING;
    } else if (size > oldsize) {
        // flush+seek if not already at end
        if (file->pos != oldsize) {
            vznncv_lfs_soff_t res = vznncv_lfs_file_seek(vznncv_lfs, file, 0, VZNNCV_LFS_SEEK_END);
            if (res < 0) {
                VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate -> %"PRId32, res);
                return (int)res;
            }
        }

        // fill with zeros
        while (file->pos < size) {
            vznncv_lfs_ssize_t res = vznncv_lfs_file_write(vznncv_lfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate -> %"PRId32, res);
                return (int)res;
            }
        }
    }

    // restore pos
    vznncv_lfs_soff_t res = vznncv_lfs_file_seek(vznncv_lfs, file, pos, VZNNCV_LFS_SEEK_SET);
    if (res < 0) {
      VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate -> %"PRId32, res);
      return (int)res;
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_file_truncate -> %d", 0);
    return 0;
}

vznncv_lfs_soff_t vznncv_lfs_file_tell(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_tell(%p, %p)", (void*)vznncv_lfs, (void*)file);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);
    (void)vznncv_lfs;
    VZNNCV_LFS_TRACE("vznncv_lfs_file_tell -> %"PRId32, file->pos);
    return file->pos;
}

int vznncv_lfs_file_rewind(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_rewind(%p, %p)", (void*)vznncv_lfs, (void*)file);
    vznncv_lfs_soff_t res = vznncv_lfs_file_seek(vznncv_lfs, file, 0, VZNNCV_LFS_SEEK_SET);
    if (res < 0) {
        VZNNCV_LFS_TRACE("vznncv_lfs_file_rewind -> %"PRId32, res);
        return (int)res;
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_file_rewind -> %d", 0);
    return 0;
}

vznncv_lfs_soff_t vznncv_lfs_file_size(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_file_t *file) {
    VZNNCV_LFS_TRACE("vznncv_lfs_file_size(%p, %p)", (void*)vznncv_lfs, (void*)file);
    VZNNCV_LFS_ASSERT(file->flags & VZNNCV_LFS_F_OPENED);
    (void)vznncv_lfs;
    if (file->flags & VZNNCV_LFS_F_WRITING) {
        VZNNCV_LFS_TRACE("vznncv_lfs_file_size -> %"PRId32,
                vznncv_lfs_max(file->pos, file->ctz.size));
        return vznncv_lfs_max(file->pos, file->ctz.size);
    } else {
        VZNNCV_LFS_TRACE("vznncv_lfs_file_size -> %"PRId32, file->ctz.size);
        return file->ctz.size;
    }
}


/// General fs operations ///
int vznncv_lfs_stat(vznncv_lfs_t *vznncv_lfs, const char *path, struct vznncv_lfs_info *info) {
    VZNNCV_LFS_TRACE("vznncv_lfs_stat(%p, \"%s\", %p)", (void*)vznncv_lfs, path, (void*)info);
    vznncv_lfs_mdir_t cwd;
    vznncv_lfs_stag_t tag = vznncv_lfs_dir_find(vznncv_lfs, &cwd, &path, NULL);
    if (tag < 0) {
        VZNNCV_LFS_TRACE("vznncv_lfs_stat -> %"PRId32, tag);
        return (int)tag;
    }

    int err = vznncv_lfs_dir_getinfo(vznncv_lfs, &cwd, vznncv_lfs_tag_id(tag), info);
    VZNNCV_LFS_TRACE("vznncv_lfs_stat -> %d", err);
    return err;
}

int vznncv_lfs_remove(vznncv_lfs_t *vznncv_lfs, const char *path) {
    VZNNCV_LFS_TRACE("vznncv_lfs_remove(%p, \"%s\")", (void*)vznncv_lfs, path);
    // deorphan if we haven't yet, needed at most once after poweron
    int err = vznncv_lfs_fs_forceconsistency(vznncv_lfs);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %d", err);
        return err;
    }

    vznncv_lfs_mdir_t cwd;
    vznncv_lfs_stag_t tag = vznncv_lfs_dir_find(vznncv_lfs, &cwd, &path, NULL);
    if (tag < 0 || vznncv_lfs_tag_id(tag) == 0x3ff) {
        VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %"PRId32, (tag < 0) ? tag : VZNNCV_LFS_ERR_INVAL);
        return (tag < 0) ? (int)tag : VZNNCV_LFS_ERR_INVAL;
    }

    struct vznncv_lfs_mlist dir;
    dir.next = vznncv_lfs->mlist;
    if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_TYPE_DIR) {
        // must be empty before removal
        vznncv_lfs_block_t pair[2];
        vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, &cwd, VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, vznncv_lfs_tag_id(tag), 8), pair);
        if (res < 0) {
            VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %"PRId32, res);
            return (int)res;
        }
        vznncv_lfs_pair_fromle32(pair);

        err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir.m, pair);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %d", err);
            return err;
        }

        if (dir.m.count > 0 || dir.m.split) {
            VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %d", VZNNCV_LFS_ERR_NOTEMPTY);
            return VZNNCV_LFS_ERR_NOTEMPTY;
        }

        // mark fs as orphaned
        vznncv_lfs_fs_preporphans(vznncv_lfs, +1);

        // I know it's crazy but yes, dir can be changed by our parent's
        // commit (if predecessor is child)
        dir.type = 0;
        dir.id = 0;
        vznncv_lfs->mlist = &dir;
    }

    // delete the entry
    err = vznncv_lfs_dir_commit(vznncv_lfs, &cwd, VZNNCV_LFS_MKATTRS(
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DELETE, vznncv_lfs_tag_id(tag), 0), NULL}));
    if (err) {
        vznncv_lfs->mlist = dir.next;
        VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %d", err);
        return err;
    }

    vznncv_lfs->mlist = dir.next;
    if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_TYPE_DIR) {
        // fix orphan
        vznncv_lfs_fs_preporphans(vznncv_lfs, -1);

        err = vznncv_lfs_fs_pred(vznncv_lfs, dir.m.pair, &cwd);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %d", err);
            return err;
        }

        err = vznncv_lfs_dir_drop(vznncv_lfs, &cwd, &dir.m);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %d", err);
            return err;
        }
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_remove -> %d", 0);
    return 0;
}

int vznncv_lfs_rename(vznncv_lfs_t *vznncv_lfs, const char *oldpath, const char *newpath) {
    VZNNCV_LFS_TRACE("vznncv_lfs_rename(%p, \"%s\", \"%s\")", (void*)vznncv_lfs, oldpath, newpath);

    // deorphan if we haven't yet, needed at most once after poweron
    int err = vznncv_lfs_fs_forceconsistency(vznncv_lfs);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", err);
        return err;
    }

    // find old entry
    vznncv_lfs_mdir_t oldcwd;
    vznncv_lfs_stag_t oldtag = vznncv_lfs_dir_find(vznncv_lfs, &oldcwd, &oldpath, NULL);
    if (oldtag < 0 || vznncv_lfs_tag_id(oldtag) == 0x3ff) {
        VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %"PRId32,
                (oldtag < 0) ? oldtag : VZNNCV_LFS_ERR_INVAL);
        return (oldtag < 0) ? (int)oldtag : VZNNCV_LFS_ERR_INVAL;
    }

    // find new entry
    vznncv_lfs_mdir_t newcwd;
    uint16_t newid;
    vznncv_lfs_stag_t prevtag = vznncv_lfs_dir_find(vznncv_lfs, &newcwd, &newpath, &newid);
    if ((prevtag < 0 || vznncv_lfs_tag_id(prevtag) == 0x3ff) &&
            !(prevtag == VZNNCV_LFS_ERR_NOENT && newid != 0x3ff)) {
        VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %"PRId32,
            (prevtag < 0) ? prevtag : VZNNCV_LFS_ERR_INVAL);
        return (prevtag < 0) ? (int)prevtag : VZNNCV_LFS_ERR_INVAL;
    }

    // if we're in the same pair there's a few special cases...
    bool samepair = (vznncv_lfs_pair_cmp(oldcwd.pair, newcwd.pair) == 0);
    uint16_t newoldid = vznncv_lfs_tag_id(oldtag);

    struct vznncv_lfs_mlist prevdir;
    prevdir.next = vznncv_lfs->mlist;
    if (prevtag == VZNNCV_LFS_ERR_NOENT) {
        // check that name fits
        vznncv_lfs_size_t nlen = strlen(newpath);
        if (nlen > vznncv_lfs->name_max) {
            VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", VZNNCV_LFS_ERR_NAMETOOLONG);
            return VZNNCV_LFS_ERR_NAMETOOLONG;
        }

        // there is a small chance we are being renamed in the same
        // directory/ to an id less than our old id, the global update
        // to handle this is a bit messy
        if (samepair && newid <= newoldid) {
            newoldid += 1;
        }
    } else if (vznncv_lfs_tag_type3(prevtag) != vznncv_lfs_tag_type3(oldtag)) {
        VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", VZNNCV_LFS_ERR_ISDIR);
        return VZNNCV_LFS_ERR_ISDIR;
    } else if (samepair && newid == newoldid) {
        // we're renaming to ourselves??
        VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", 0);
        return 0;
    } else if (vznncv_lfs_tag_type3(prevtag) == VZNNCV_LFS_TYPE_DIR) {
        // must be empty before removal
        vznncv_lfs_block_t prevpair[2];
        vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, &newcwd, VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, newid, 8), prevpair);
        if (res < 0) {
            VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %"PRId32, res);
            return (int)res;
        }
        vznncv_lfs_pair_fromle32(prevpair);

        // must be empty before removal
        err = vznncv_lfs_dir_fetch(vznncv_lfs, &prevdir.m, prevpair);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", err);
            return err;
        }

        if (prevdir.m.count > 0 || prevdir.m.split) {
            VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", VZNNCV_LFS_ERR_NOTEMPTY);
            return VZNNCV_LFS_ERR_NOTEMPTY;
        }

        // mark fs as orphaned
        vznncv_lfs_fs_preporphans(vznncv_lfs, +1);

        // I know it's crazy but yes, dir can be changed by our parent's
        // commit (if predecessor is child)
        prevdir.type = 0;
        prevdir.id = 0;
        vznncv_lfs->mlist = &prevdir;
    }

    if (!samepair) {
        vznncv_lfs_fs_prepmove(vznncv_lfs, newoldid, oldcwd.pair);
    }

    // move over all attributes
    err = vznncv_lfs_dir_commit(vznncv_lfs, &newcwd, VZNNCV_LFS_MKATTRS(
            {VZNNCV_LFS_MKTAG_IF(prevtag != VZNNCV_LFS_ERR_NOENT,
                VZNNCV_LFS_TYPE_DELETE, newid, 0), NULL},
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CREATE, newid, 0), NULL},
            {VZNNCV_LFS_MKTAG(vznncv_lfs_tag_type3(oldtag), newid, strlen(newpath)), newpath},
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_FROM_MOVE, newid, vznncv_lfs_tag_id(oldtag)), &oldcwd},
            {VZNNCV_LFS_MKTAG_IF(samepair,
                VZNNCV_LFS_TYPE_DELETE, newoldid, 0), NULL}));
    if (err) {
        vznncv_lfs->mlist = prevdir.next;
        VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", err);
        return err;
    }

    // let commit clean up after move (if we're different! otherwise move
    // logic already fixed it for us)
    if (!samepair && vznncv_lfs_gstate_hasmove(&vznncv_lfs->gstate)) {
        // prep gstate and delete move id
        vznncv_lfs_fs_prepmove(vznncv_lfs, 0x3ff, NULL);
        err = vznncv_lfs_dir_commit(vznncv_lfs, &oldcwd, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DELETE, vznncv_lfs_tag_id(oldtag), 0), NULL}));
        if (err) {
            vznncv_lfs->mlist = prevdir.next;
            VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", err);
            return err;
        }
    }

    vznncv_lfs->mlist = prevdir.next;
    if (prevtag != VZNNCV_LFS_ERR_NOENT && vznncv_lfs_tag_type3(prevtag) == VZNNCV_LFS_TYPE_DIR) {
        // fix orphan
        vznncv_lfs_fs_preporphans(vznncv_lfs, -1);

        err = vznncv_lfs_fs_pred(vznncv_lfs, prevdir.m.pair, &newcwd);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", err);
            return err;
        }

        err = vznncv_lfs_dir_drop(vznncv_lfs, &newcwd, &prevdir.m);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", err);
            return err;
        }
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_rename -> %d", 0);
    return 0;
}

vznncv_lfs_ssize_t vznncv_lfs_getattr(vznncv_lfs_t *vznncv_lfs, const char *path,
        uint8_t type, void *buffer, vznncv_lfs_size_t size) {
    VZNNCV_LFS_TRACE("vznncv_lfs_getattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)vznncv_lfs, path, type, buffer, size);
    vznncv_lfs_mdir_t cwd;
    vznncv_lfs_stag_t tag = vznncv_lfs_dir_find(vznncv_lfs, &cwd, &path, NULL);
    if (tag < 0) {
        VZNNCV_LFS_TRACE("vznncv_lfs_getattr -> %"PRId32, tag);
        return tag;
    }

    uint16_t id = vznncv_lfs_tag_id(tag);
    if (id == 0x3ff) {
        // special case for root
        id = 0;
        int err = vznncv_lfs_dir_fetch(vznncv_lfs, &cwd, vznncv_lfs->root);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_getattr -> %d", err);
            return err;
        }
    }

    tag = vznncv_lfs_dir_get(vznncv_lfs, &cwd, VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0),
            VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_USERATTR + type,
                id, vznncv_lfs_min(size, vznncv_lfs->attr_max)),
            buffer);
    if (tag < 0) {
        if (tag == VZNNCV_LFS_ERR_NOENT) {
            VZNNCV_LFS_TRACE("vznncv_lfs_getattr -> %d", VZNNCV_LFS_ERR_NOATTR);
            return VZNNCV_LFS_ERR_NOATTR;
        }

        VZNNCV_LFS_TRACE("vznncv_lfs_getattr -> %"PRId32, tag);
        return tag;
    }

    size = vznncv_lfs_tag_size(tag);
    VZNNCV_LFS_TRACE("vznncv_lfs_getattr -> %"PRId32, size);
    return size;
}

static int vznncv_lfs_commitattr(vznncv_lfs_t *vznncv_lfs, const char *path,
        uint8_t type, const void *buffer, vznncv_lfs_size_t size) {
    vznncv_lfs_mdir_t cwd;
    vznncv_lfs_stag_t tag = vznncv_lfs_dir_find(vznncv_lfs, &cwd, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    uint16_t id = vznncv_lfs_tag_id(tag);
    if (id == 0x3ff) {
        // special case for root
        id = 0;
        int err = vznncv_lfs_dir_fetch(vznncv_lfs, &cwd, vznncv_lfs->root);
        if (err) {
            return err;
        }
    }

    return vznncv_lfs_dir_commit(vznncv_lfs, &cwd, VZNNCV_LFS_MKATTRS(
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_USERATTR + type, id, size), buffer}));
}

int vznncv_lfs_setattr(vznncv_lfs_t *vznncv_lfs, const char *path,
        uint8_t type, const void *buffer, vznncv_lfs_size_t size) {
    VZNNCV_LFS_TRACE("vznncv_lfs_setattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)vznncv_lfs, path, type, buffer, size);
    if (size > vznncv_lfs->attr_max) {
        VZNNCV_LFS_TRACE("vznncv_lfs_setattr -> %d", VZNNCV_LFS_ERR_NOSPC);
        return VZNNCV_LFS_ERR_NOSPC;
    }

    int err = vznncv_lfs_commitattr(vznncv_lfs, path, type, buffer, size);
    VZNNCV_LFS_TRACE("vznncv_lfs_setattr -> %d", err);
    return err;
}

int vznncv_lfs_removeattr(vznncv_lfs_t *vznncv_lfs, const char *path, uint8_t type) {
    VZNNCV_LFS_TRACE("vznncv_lfs_removeattr(%p, \"%s\", %"PRIu8")", (void*)vznncv_lfs, path, type);
    int err = vznncv_lfs_commitattr(vznncv_lfs, path, type, NULL, 0x3ff);
    VZNNCV_LFS_TRACE("vznncv_lfs_removeattr -> %d", err);
    return err;
}


/// Filesystem operations ///
static int vznncv_lfs_init(vznncv_lfs_t *vznncv_lfs, const struct vznncv_lfs_config *cfg) {
    vznncv_lfs->cfg = cfg;
    int err = 0;

    // validate that the vznncv_lfs-cfg sizes were initiated properly before
    // performing any arithmetic logics with them
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->read_size != 0);
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->prog_size != 0);
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->cache_size != 0);

    // check that block size is a multiple of cache size is a multiple
    // of prog and read sizes
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->cache_size % vznncv_lfs->cfg->read_size == 0);
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->cache_size % vznncv_lfs->cfg->prog_size == 0);
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->block_size % vznncv_lfs->cfg->cache_size == 0);

    // check that the block size is large enough to fit ctz pointers
    VZNNCV_LFS_ASSERT(4*vznncv_lfs_npw2(0xffffffff / (vznncv_lfs->cfg->block_size-2*4))
            <= vznncv_lfs->cfg->block_size);

    // block_cycles = 0 is no longer supported.
    //
    // block_cycles is the number of erase cycles before littlefs evicts
    // metadata logs as a part of wear leveling. Suggested values are in the
    // range of 100-1000, or set block_cycles to -1 to disable block-level
    // wear-leveling.
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->block_cycles != 0);


    // setup read cache
    if (vznncv_lfs->cfg->read_buffer) {
        vznncv_lfs->rcache.buffer = vznncv_lfs->cfg->read_buffer;
    } else {
        vznncv_lfs->rcache.buffer = vznncv_lfs_malloc(vznncv_lfs->cfg->cache_size);
        if (!vznncv_lfs->rcache.buffer) {
            err = VZNNCV_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // setup program cache
    if (vznncv_lfs->cfg->prog_buffer) {
        vznncv_lfs->pcache.buffer = vznncv_lfs->cfg->prog_buffer;
    } else {
        vznncv_lfs->pcache.buffer = vznncv_lfs_malloc(vznncv_lfs->cfg->cache_size);
        if (!vznncv_lfs->pcache.buffer) {
            err = VZNNCV_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // zero to avoid information leaks
    vznncv_lfs_cache_zero(vznncv_lfs, &vznncv_lfs->rcache);
    vznncv_lfs_cache_zero(vznncv_lfs, &vznncv_lfs->pcache);

    // setup lookahead, must be multiple of 64-bits, 32-bit aligned
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->lookahead_size > 0);
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->lookahead_size % 8 == 0 &&
            (uintptr_t)vznncv_lfs->cfg->lookahead_buffer % 4 == 0);
    if (vznncv_lfs->cfg->lookahead_buffer) {
        vznncv_lfs->free.buffer = vznncv_lfs->cfg->lookahead_buffer;
    } else {
        vznncv_lfs->free.buffer = vznncv_lfs_malloc(vznncv_lfs->cfg->lookahead_size);
        if (!vznncv_lfs->free.buffer) {
            err = VZNNCV_LFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    // check that the size limits are sane
    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->name_max <= VZNNCV_LFS_NAME_MAX);
    vznncv_lfs->name_max = vznncv_lfs->cfg->name_max;
    if (!vznncv_lfs->name_max) {
        vznncv_lfs->name_max = VZNNCV_LFS_NAME_MAX;
    }

    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->file_max <= VZNNCV_LFS_FILE_MAX);
    vznncv_lfs->file_max = vznncv_lfs->cfg->file_max;
    if (!vznncv_lfs->file_max) {
        vznncv_lfs->file_max = VZNNCV_LFS_FILE_MAX;
    }

    VZNNCV_LFS_ASSERT(vznncv_lfs->cfg->attr_max <= VZNNCV_LFS_ATTR_MAX);
    vznncv_lfs->attr_max = vznncv_lfs->cfg->attr_max;
    if (!vznncv_lfs->attr_max) {
        vznncv_lfs->attr_max = VZNNCV_LFS_ATTR_MAX;
    }

    // setup default state
    vznncv_lfs->root[0] = VZNNCV_LFS_BLOCK_NULL;
    vznncv_lfs->root[1] = VZNNCV_LFS_BLOCK_NULL;
    vznncv_lfs->mlist = NULL;
    vznncv_lfs->seed = 0;
    vznncv_lfs->gdisk = (vznncv_lfs_gstate_t){0};
    vznncv_lfs->gstate = (vznncv_lfs_gstate_t){0};
    vznncv_lfs->gdelta = (vznncv_lfs_gstate_t){0};
#ifdef VZNNCV_LFS_MIGRATE
    vznncv_lfs->vznncv_lfs1 = NULL;
#endif

    return 0;

cleanup:
    vznncv_lfs_deinit(vznncv_lfs);
    return err;
}

static int vznncv_lfs_deinit(vznncv_lfs_t *vznncv_lfs) {
    // free allocated memory
    if (!vznncv_lfs->cfg->read_buffer) {
        vznncv_lfs_free(vznncv_lfs->rcache.buffer);
    }

    if (!vznncv_lfs->cfg->prog_buffer) {
        vznncv_lfs_free(vznncv_lfs->pcache.buffer);
    }

    if (!vznncv_lfs->cfg->lookahead_buffer) {
        vznncv_lfs_free(vznncv_lfs->free.buffer);
    }

    return 0;
}

int vznncv_lfs_format(vznncv_lfs_t *vznncv_lfs, const struct vznncv_lfs_config *cfg) {
    VZNNCV_LFS_TRACE("vznncv_lfs_format(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)vznncv_lfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);
    int err = 0;
    {
        err = vznncv_lfs_init(vznncv_lfs, cfg);
        if (err) {
            VZNNCV_LFS_TRACE("vznncv_lfs_format -> %d", err);
            return err;
        }

        // create free lookahead
        memset(vznncv_lfs->free.buffer, 0, vznncv_lfs->cfg->lookahead_size);
        vznncv_lfs->free.off = 0;
        vznncv_lfs->free.size = vznncv_lfs_min(8*vznncv_lfs->cfg->lookahead_size,
                vznncv_lfs->cfg->block_count);
        vznncv_lfs->free.i = 0;
        vznncv_lfs_alloc_ack(vznncv_lfs);

        // create root dir
        vznncv_lfs_mdir_t root;
        err = vznncv_lfs_dir_alloc(vznncv_lfs, &root);
        if (err) {
            goto cleanup;
        }

        // write one superblock
        vznncv_lfs_superblock_t superblock = {
            .version     = VZNNCV_LFS_DISK_VERSION,
            .block_size  = vznncv_lfs->cfg->block_size,
            .block_count = vznncv_lfs->cfg->block_count,
            .name_max    = vznncv_lfs->name_max,
            .file_max    = vznncv_lfs->file_max,
            .attr_max    = vznncv_lfs->attr_max,
        };

        vznncv_lfs_superblock_tole32(&superblock);
        err = vznncv_lfs_dir_commit(vznncv_lfs, &root, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CREATE, 0, 0), NULL},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_SUPERBLOCK, 0, 8), "littlefs"},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock}));
        if (err) {
            goto cleanup;
        }

        // sanity check that fetch works
        err = vznncv_lfs_dir_fetch(vznncv_lfs, &root, (const vznncv_lfs_block_t[2]){0, 1});
        if (err) {
            goto cleanup;
        }

        // force compaction to prevent accidentally mounting any
        // older version of littlefs that may live on disk
        root.erased = false;
        err = vznncv_lfs_dir_commit(vznncv_lfs, &root, NULL, 0);
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    vznncv_lfs_deinit(vznncv_lfs);
    VZNNCV_LFS_TRACE("vznncv_lfs_format -> %d", err);
    return err;
}

int vznncv_lfs_mount(vznncv_lfs_t *vznncv_lfs, const struct vznncv_lfs_config *cfg) {
    VZNNCV_LFS_TRACE("vznncv_lfs_mount(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)vznncv_lfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);
    int err = vznncv_lfs_init(vznncv_lfs, cfg);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_mount -> %d", err);
        return err;
    }

    // scan directory blocks for superblock and any global updates
    vznncv_lfs_mdir_t dir = {.tail = {0, 1}};
    vznncv_lfs_block_t cycle = 0;
    while (!vznncv_lfs_pair_isnull(dir.tail)) {
        if (cycle >= vznncv_lfs->cfg->block_count/2) {
            // loop detected
            err = VZNNCV_LFS_ERR_CORRUPT;
            goto cleanup;
        }
        cycle += 1;

        // fetch next block in tail list
        vznncv_lfs_stag_t tag = vznncv_lfs_dir_fetchmatch(vznncv_lfs, &dir, dir.tail,
                VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0),
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_SUPERBLOCK, 0, 8),
                NULL,
                vznncv_lfs_dir_find_match, &(struct vznncv_lfs_dir_find_match){
                    vznncv_lfs, "littlefs", 8});
        if (tag < 0) {
            err = tag;
            goto cleanup;
        }

        // has superblock?
        if (tag && !vznncv_lfs_tag_isdelete(tag)) {
            // update root
            vznncv_lfs->root[0] = dir.pair[0];
            vznncv_lfs->root[1] = dir.pair[1];

            // grab superblock
            vznncv_lfs_superblock_t superblock;
            tag = vznncv_lfs_dir_get(vznncv_lfs, &dir, VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock);
            if (tag < 0) {
                err = tag;
                goto cleanup;
            }
            vznncv_lfs_superblock_fromle32(&superblock);

            // check version
            uint16_t major_version = (0xffff & (superblock.version >> 16));
            uint16_t minor_version = (0xffff & (superblock.version >>  0));
            if ((major_version != VZNNCV_LFS_DISK_VERSION_MAJOR ||
                 minor_version > VZNNCV_LFS_DISK_VERSION_MINOR)) {
                VZNNCV_LFS_ERROR("Invalid version v%"PRIu16".%"PRIu16,
                        major_version, minor_version);
                err = VZNNCV_LFS_ERR_INVAL;
                goto cleanup;
            }

            // check superblock configuration
            if (superblock.name_max) {
                if (superblock.name_max > vznncv_lfs->name_max) {
                    VZNNCV_LFS_ERROR("Unsupported name_max (%"PRIu32" > %"PRIu32")",
                            superblock.name_max, vznncv_lfs->name_max);
                    err = VZNNCV_LFS_ERR_INVAL;
                    goto cleanup;
                }

                vznncv_lfs->name_max = superblock.name_max;
            }

            if (superblock.file_max) {
                if (superblock.file_max > vznncv_lfs->file_max) {
                    VZNNCV_LFS_ERROR("Unsupported file_max (%"PRIu32" > %"PRIu32")",
                            superblock.file_max, vznncv_lfs->file_max);
                    err = VZNNCV_LFS_ERR_INVAL;
                    goto cleanup;
                }

                vznncv_lfs->file_max = superblock.file_max;
            }

            if (superblock.attr_max) {
                if (superblock.attr_max > vznncv_lfs->attr_max) {
                    VZNNCV_LFS_ERROR("Unsupported attr_max (%"PRIu32" > %"PRIu32")",
                            superblock.attr_max, vznncv_lfs->attr_max);
                    err = VZNNCV_LFS_ERR_INVAL;
                    goto cleanup;
                }

                vznncv_lfs->attr_max = superblock.attr_max;
            }
        }

        // has gstate?
        err = vznncv_lfs_dir_getgstate(vznncv_lfs, &dir, &vznncv_lfs->gstate);
        if (err) {
            goto cleanup;
        }
    }

    // found superblock?
    if (vznncv_lfs_pair_isnull(vznncv_lfs->root)) {
        err = VZNNCV_LFS_ERR_INVAL;
        goto cleanup;
    }

    // update littlefs with gstate
    if (!vznncv_lfs_gstate_iszero(&vznncv_lfs->gstate)) {
        VZNNCV_LFS_DEBUG("Found pending gstate 0x%08"PRIx32"%08"PRIx32"%08"PRIx32,
                vznncv_lfs->gstate.tag,
                vznncv_lfs->gstate.pair[0],
                vznncv_lfs->gstate.pair[1]);
    }
    vznncv_lfs->gstate.tag += !vznncv_lfs_tag_isvalid(vznncv_lfs->gstate.tag);
    vznncv_lfs->gdisk = vznncv_lfs->gstate;

    // setup free lookahead
    vznncv_lfs_alloc_reset(vznncv_lfs);

    VZNNCV_LFS_TRACE("vznncv_lfs_mount -> %d", 0);
    return 0;

cleanup:
    vznncv_lfs_unmount(vznncv_lfs);
    VZNNCV_LFS_TRACE("vznncv_lfs_mount -> %d", err);
    return err;
}

int vznncv_lfs_unmount(vznncv_lfs_t *vznncv_lfs) {
    VZNNCV_LFS_TRACE("vznncv_lfs_unmount(%p)", (void*)vznncv_lfs);
    int err = vznncv_lfs_deinit(vznncv_lfs);
    VZNNCV_LFS_TRACE("vznncv_lfs_unmount -> %d", err);
    return err;
}


/// Filesystem filesystem operations ///
int vznncv_lfs_fs_traverseraw(vznncv_lfs_t *vznncv_lfs,
        int (*cb)(void *data, vznncv_lfs_block_t block), void *data,
        bool includeorphans) {
    // iterate over metadata pairs
    vznncv_lfs_mdir_t dir = {.tail = {0, 1}};

#ifdef VZNNCV_LFS_MIGRATE
    // also consider v1 blocks during migration
    if (vznncv_lfs->vznncv_lfs1) {
        int err = vznncv_lfs1_traverse(vznncv_lfs, cb, data);
        if (err) {
            return err;
        }

        dir.tail[0] = vznncv_lfs->root[0];
        dir.tail[1] = vznncv_lfs->root[1];
    }
#endif

    vznncv_lfs_block_t cycle = 0;
    while (!vznncv_lfs_pair_isnull(dir.tail)) {
        if (cycle >= vznncv_lfs->cfg->block_count/2) {
            // loop detected
            return VZNNCV_LFS_ERR_CORRUPT;
        }
        cycle += 1;

        for (int i = 0; i < 2; i++) {
            int err = cb(data, dir.tail[i]);
            if (err) {
                return err;
            }
        }

        // iterate through ids in directory
        int err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir, dir.tail);
        if (err) {
            return err;
        }

        for (uint16_t id = 0; id < dir.count; id++) {
            struct vznncv_lfs_ctz ctz;
            vznncv_lfs_stag_t tag = vznncv_lfs_dir_get(vznncv_lfs, &dir, VZNNCV_LFS_MKTAG(0x700, 0x3ff, 0),
                    VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
            if (tag < 0) {
                if (tag == VZNNCV_LFS_ERR_NOENT) {
                    continue;
                }
                return tag;
            }
            vznncv_lfs_ctz_fromle32(&ctz);

            if (vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_TYPE_CTZSTRUCT) {
                err = vznncv_lfs_ctz_traverse(vznncv_lfs, NULL, &vznncv_lfs->rcache,
                        ctz.head, ctz.size, cb, data);
                if (err) {
                    return err;
                }
            } else if (includeorphans && 
                    vznncv_lfs_tag_type3(tag) == VZNNCV_LFS_TYPE_DIRSTRUCT) {
                for (int i = 0; i < 2; i++) {
                    err = cb(data, (&ctz.head)[i]);
                    if (err) {
                        return err;
                    }
                }
            }
        }
    }

    // iterate over any open files
    for (vznncv_lfs_file_t *f = (vznncv_lfs_file_t*)vznncv_lfs->mlist; f; f = f->next) {
        if (f->type != VZNNCV_LFS_TYPE_REG) {
            continue;
        }

        if ((f->flags & VZNNCV_LFS_F_DIRTY) && !(f->flags & VZNNCV_LFS_F_INLINE)) {
            int err = vznncv_lfs_ctz_traverse(vznncv_lfs, &f->cache, &vznncv_lfs->rcache,
                    f->ctz.head, f->ctz.size, cb, data);
            if (err) {
                return err;
            }
        }

        if ((f->flags & VZNNCV_LFS_F_WRITING) && !(f->flags & VZNNCV_LFS_F_INLINE)) {
            int err = vznncv_lfs_ctz_traverse(vznncv_lfs, &f->cache, &vznncv_lfs->rcache,
                    f->block, f->pos, cb, data);
            if (err) {
                return err;
            }
        }
    }

    return 0;
}

int vznncv_lfs_fs_traverse(vznncv_lfs_t *vznncv_lfs,
        int (*cb)(void *data, vznncv_lfs_block_t block), void *data) {
    VZNNCV_LFS_TRACE("vznncv_lfs_fs_traverse(%p, %p, %p)",
            (void*)vznncv_lfs, (void*)(uintptr_t)cb, data);
    int err = vznncv_lfs_fs_traverseraw(vznncv_lfs, cb, data, true);
    VZNNCV_LFS_TRACE("vznncv_lfs_fs_traverse -> %d", 0);
    return err;
}

static int vznncv_lfs_fs_pred(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_block_t pair[2], vznncv_lfs_mdir_t *pdir) {
    // iterate over all directory directory entries
    pdir->tail[0] = 0;
    pdir->tail[1] = 1;
    vznncv_lfs_block_t cycle = 0;
    while (!vznncv_lfs_pair_isnull(pdir->tail)) {
        if (cycle >= vznncv_lfs->cfg->block_count/2) {
            // loop detected
            return VZNNCV_LFS_ERR_CORRUPT;
        }
        cycle += 1;

        if (vznncv_lfs_pair_cmp(pdir->tail, pair) == 0) {
            return 0;
        }

        int err = vznncv_lfs_dir_fetch(vznncv_lfs, pdir, pdir->tail);
        if (err) {
            return err;
        }
    }

    return VZNNCV_LFS_ERR_NOENT;
}

struct vznncv_lfs_fs_parent_match {
    vznncv_lfs_t *vznncv_lfs;
    const vznncv_lfs_block_t pair[2];
};

static int vznncv_lfs_fs_parent_match(void *data,
        vznncv_lfs_tag_t tag, const void *buffer) {
    struct vznncv_lfs_fs_parent_match *find = data;
    vznncv_lfs_t *vznncv_lfs = find->vznncv_lfs;
    const struct vznncv_lfs_diskoff *disk = buffer;
    (void)tag;

    vznncv_lfs_block_t child[2];
    int err = vznncv_lfs_bd_read(vznncv_lfs,
            &vznncv_lfs->pcache, &vznncv_lfs->rcache, vznncv_lfs->cfg->block_size,
            disk->block, disk->off, &child, sizeof(child));
    if (err) {
        return err;
    }

    vznncv_lfs_pair_fromle32(child);
    return (vznncv_lfs_pair_cmp(child, find->pair) == 0) ? VZNNCV_LFS_CMP_EQ : VZNNCV_LFS_CMP_LT;
}

static vznncv_lfs_stag_t vznncv_lfs_fs_parent(vznncv_lfs_t *vznncv_lfs, const vznncv_lfs_block_t pair[2],
        vznncv_lfs_mdir_t *parent) {
    // use fetchmatch with callback to find pairs
    parent->tail[0] = 0;
    parent->tail[1] = 1;
    vznncv_lfs_block_t cycle = 0;
    while (!vznncv_lfs_pair_isnull(parent->tail)) {
        if (cycle >= vznncv_lfs->cfg->block_count/2) {
            // loop detected
            return VZNNCV_LFS_ERR_CORRUPT;
        }
        cycle += 1;

        vznncv_lfs_stag_t tag = vznncv_lfs_dir_fetchmatch(vznncv_lfs, parent, parent->tail,
                VZNNCV_LFS_MKTAG(0x7ff, 0, 0x3ff),
                VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DIRSTRUCT, 0, 8),
                NULL,
                vznncv_lfs_fs_parent_match, &(struct vznncv_lfs_fs_parent_match){
                    vznncv_lfs, {pair[0], pair[1]}});
        if (tag && tag != VZNNCV_LFS_ERR_NOENT) {
            return tag;
        }
    }

    return VZNNCV_LFS_ERR_NOENT;
}

static int vznncv_lfs_fs_relocate(vznncv_lfs_t *vznncv_lfs,
        const vznncv_lfs_block_t oldpair[2], vznncv_lfs_block_t newpair[2]) {
    // update internal root
    if (vznncv_lfs_pair_cmp(oldpair, vznncv_lfs->root) == 0) {
        vznncv_lfs->root[0] = newpair[0];
        vznncv_lfs->root[1] = newpair[1];
    }

    // update internally tracked dirs
    for (struct vznncv_lfs_mlist *d = vznncv_lfs->mlist; d; d = d->next) {
        if (vznncv_lfs_pair_cmp(oldpair, d->m.pair) == 0) {
            d->m.pair[0] = newpair[0];
            d->m.pair[1] = newpair[1];
        }

        if (d->type == VZNNCV_LFS_TYPE_DIR &&
                vznncv_lfs_pair_cmp(oldpair, ((vznncv_lfs_dir_t*)d)->head) == 0) {
            ((vznncv_lfs_dir_t*)d)->head[0] = newpair[0];
            ((vznncv_lfs_dir_t*)d)->head[1] = newpair[1];
        }
    }

    // find parent
    vznncv_lfs_mdir_t parent;
    vznncv_lfs_stag_t tag = vznncv_lfs_fs_parent(vznncv_lfs, oldpair, &parent);
    if (tag < 0 && tag != VZNNCV_LFS_ERR_NOENT) {
        return tag;
    }

    if (tag != VZNNCV_LFS_ERR_NOENT) {
        // update disk, this creates a desync
        vznncv_lfs_fs_preporphans(vznncv_lfs, +1);

        // fix pending move in this pair? this looks like an optimization but
        // is in fact _required_ since relocating may outdate the move.
        uint16_t moveid = 0x3ff;
        if (vznncv_lfs_gstate_hasmovehere(&vznncv_lfs->gstate, parent.pair)) {
            moveid = vznncv_lfs_tag_id(vznncv_lfs->gstate.tag);
            VZNNCV_LFS_DEBUG("Fixing move while relocating "
                    "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                    parent.pair[0], parent.pair[1], moveid);
            vznncv_lfs_fs_prepmove(vznncv_lfs, 0x3ff, NULL);
            if (moveid < vznncv_lfs_tag_id(tag)) {
                tag -= VZNNCV_LFS_MKTAG(0, 1, 0);
            }
        }

        vznncv_lfs_pair_tole32(newpair);
        int err = vznncv_lfs_dir_commit(vznncv_lfs, &parent, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG_IF(moveid != 0x3ff,
                    VZNNCV_LFS_TYPE_DELETE, moveid, 0), NULL},
                {tag, newpair}));
        vznncv_lfs_pair_fromle32(newpair);
        if (err) {
            return err;
        }

        // next step, clean up orphans
        vznncv_lfs_fs_preporphans(vznncv_lfs, -1);
    }

    // find pred
    int err = vznncv_lfs_fs_pred(vznncv_lfs, oldpair, &parent);
    if (err && err != VZNNCV_LFS_ERR_NOENT) {
        return err;
    }

    // if we can't find dir, it must be new
    if (err != VZNNCV_LFS_ERR_NOENT) {
        // fix pending move in this pair? this looks like an optimization but
        // is in fact _required_ since relocating may outdate the move.
        uint16_t moveid = 0x3ff;
        if (vznncv_lfs_gstate_hasmovehere(&vznncv_lfs->gstate, parent.pair)) {
            moveid = vznncv_lfs_tag_id(vznncv_lfs->gstate.tag);
            VZNNCV_LFS_DEBUG("Fixing move while relocating "
                    "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                    parent.pair[0], parent.pair[1], moveid);
            vznncv_lfs_fs_prepmove(vznncv_lfs, 0x3ff, NULL);
        }

        // replace bad pair, either we clean up desync, or no desync occured
        vznncv_lfs_pair_tole32(newpair);
        err = vznncv_lfs_dir_commit(vznncv_lfs, &parent, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG_IF(moveid != 0x3ff,
                    VZNNCV_LFS_TYPE_DELETE, moveid, 0), NULL},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_TAIL + parent.split, 0x3ff, 8), newpair}));
        vznncv_lfs_pair_fromle32(newpair);
        if (err) {
            return err;
        }
    }

    return 0;
}

static void vznncv_lfs_fs_preporphans(vznncv_lfs_t *vznncv_lfs, int8_t orphans) {
    VZNNCV_LFS_ASSERT(vznncv_lfs_tag_size(vznncv_lfs->gstate.tag) > 0 || orphans >= 0);
    vznncv_lfs->gstate.tag += orphans;
    vznncv_lfs->gstate.tag = ((vznncv_lfs->gstate.tag & ~VZNNCV_LFS_MKTAG(0x800, 0, 0)) |
            ((uint32_t)vznncv_lfs_gstate_hasorphans(&vznncv_lfs->gstate) << 31));
}

static void vznncv_lfs_fs_prepmove(vznncv_lfs_t *vznncv_lfs,
        uint16_t id, const vznncv_lfs_block_t pair[2]) {
    vznncv_lfs->gstate.tag = ((vznncv_lfs->gstate.tag & ~VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0)) |
            ((id != 0x3ff) ? VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DELETE, id, 0) : 0));
    vznncv_lfs->gstate.pair[0] = (id != 0x3ff) ? pair[0] : 0;
    vznncv_lfs->gstate.pair[1] = (id != 0x3ff) ? pair[1] : 0;
}

static int vznncv_lfs_fs_demove(vznncv_lfs_t *vznncv_lfs) {
    if (!vznncv_lfs_gstate_hasmove(&vznncv_lfs->gdisk)) {
        return 0;
    }

    // Fix bad moves
    VZNNCV_LFS_DEBUG("Fixing move {0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16,
            vznncv_lfs->gdisk.pair[0],
            vznncv_lfs->gdisk.pair[1],
            vznncv_lfs_tag_id(vznncv_lfs->gdisk.tag));

    // fetch and delete the moved entry
    vznncv_lfs_mdir_t movedir;
    int err = vznncv_lfs_dir_fetch(vznncv_lfs, &movedir, vznncv_lfs->gdisk.pair);
    if (err) {
        return err;
    }

    // prep gstate and delete move id
    uint16_t moveid = vznncv_lfs_tag_id(vznncv_lfs->gdisk.tag);
    vznncv_lfs_fs_prepmove(vznncv_lfs, 0x3ff, NULL);
    err = vznncv_lfs_dir_commit(vznncv_lfs, &movedir, VZNNCV_LFS_MKATTRS(
            {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_DELETE, moveid, 0), NULL}));
    if (err) {
        return err;
    }

    return 0;
}

static int vznncv_lfs_fs_deorphan(vznncv_lfs_t *vznncv_lfs) {
    if (!vznncv_lfs_gstate_hasorphans(&vznncv_lfs->gstate)) {
        return 0;
    }

    // Fix any orphans
    vznncv_lfs_mdir_t pdir = {.split = true, .tail = {0, 1}};
    vznncv_lfs_mdir_t dir;

    // iterate over all directory directory entries
    while (!vznncv_lfs_pair_isnull(pdir.tail)) {
        int err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir, pdir.tail);
        if (err) {
            return err;
        }

        // check head blocks for orphans
        if (!pdir.split) {
            // check if we have a parent
            vznncv_lfs_mdir_t parent;
            vznncv_lfs_stag_t tag = vznncv_lfs_fs_parent(vznncv_lfs, pdir.tail, &parent);
            if (tag < 0 && tag != VZNNCV_LFS_ERR_NOENT) {
                return tag;
            }

            if (tag == VZNNCV_LFS_ERR_NOENT) {
                // we are an orphan
                VZNNCV_LFS_DEBUG("Fixing orphan {0x%"PRIx32", 0x%"PRIx32"}",
                        pdir.tail[0], pdir.tail[1]);

                err = vznncv_lfs_dir_drop(vznncv_lfs, &pdir, &dir);
                if (err) {
                    return err;
                }

                // refetch tail
                continue;
            }

            vznncv_lfs_block_t pair[2];
            vznncv_lfs_stag_t res = vznncv_lfs_dir_get(vznncv_lfs, &parent,
                    VZNNCV_LFS_MKTAG(0x7ff, 0x3ff, 0), tag, pair);
            if (res < 0) {
                return res;
            }
            vznncv_lfs_pair_fromle32(pair);

            if (!vznncv_lfs_pair_sync(pair, pdir.tail)) {
                // we have desynced
                VZNNCV_LFS_DEBUG("Fixing half-orphan {0x%"PRIx32", 0x%"PRIx32"} "
                            "-> {0x%"PRIx32", 0x%"PRIx32"}",
                        pdir.tail[0], pdir.tail[1], pair[0], pair[1]);

                vznncv_lfs_pair_tole32(pair);
                err = vznncv_lfs_dir_commit(vznncv_lfs, &pdir, VZNNCV_LFS_MKATTRS(
                        {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_SOFTTAIL, 0x3ff, 8), pair}));
                vznncv_lfs_pair_fromle32(pair);
                if (err) {
                    return err;
                }

                // refetch tail
                continue;
            }
        }

        pdir = dir;
    }

    // mark orphans as fixed
    vznncv_lfs_fs_preporphans(vznncv_lfs, -vznncv_lfs_gstate_getorphans(&vznncv_lfs->gstate));
    return 0;
}

static int vznncv_lfs_fs_forceconsistency(vznncv_lfs_t *vznncv_lfs) {
    int err = vznncv_lfs_fs_demove(vznncv_lfs);
    if (err) {
        return err;
    }

    err = vznncv_lfs_fs_deorphan(vznncv_lfs);
    if (err) {
        return err;
    }

    return 0;
}

static int vznncv_lfs_fs_size_count(void *p, vznncv_lfs_block_t block) {
    (void)block;
    vznncv_lfs_size_t *size = p;
    *size += 1;
    return 0;
}

vznncv_lfs_ssize_t vznncv_lfs_fs_size(vznncv_lfs_t *vznncv_lfs) {
    VZNNCV_LFS_TRACE("vznncv_lfs_fs_size(%p)", (void*)vznncv_lfs);
    vznncv_lfs_size_t size = 0;
    int err = vznncv_lfs_fs_traverseraw(vznncv_lfs, vznncv_lfs_fs_size_count, &size, false);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_fs_size -> %d", err);
        return err;
    }

    VZNNCV_LFS_TRACE("vznncv_lfs_fs_size -> %d", err);
    return size;
}

#ifdef VZNNCV_LFS_MIGRATE
////// Migration from littelfs v1 below this //////

/// Version info ///

// Software library version
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define VZNNCV_LFS1_VERSION 0x00010007
#define VZNNCV_LFS1_VERSION_MAJOR (0xffff & (VZNNCV_LFS1_VERSION >> 16))
#define VZNNCV_LFS1_VERSION_MINOR (0xffff & (VZNNCV_LFS1_VERSION >>  0))

// Version of On-disk data structures
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define VZNNCV_LFS1_DISK_VERSION 0x00010001
#define VZNNCV_LFS1_DISK_VERSION_MAJOR (0xffff & (VZNNCV_LFS1_DISK_VERSION >> 16))
#define VZNNCV_LFS1_DISK_VERSION_MINOR (0xffff & (VZNNCV_LFS1_DISK_VERSION >>  0))


/// v1 Definitions ///

// File types
enum vznncv_lfs1_type {
    VZNNCV_LFS1_TYPE_REG        = 0x11,
    VZNNCV_LFS1_TYPE_DIR        = 0x22,
    VZNNCV_LFS1_TYPE_SUPERBLOCK = 0x2e,
};

typedef struct vznncv_lfs1 {
    vznncv_lfs_block_t root[2];
} vznncv_lfs1_t;

typedef struct vznncv_lfs1_entry {
    vznncv_lfs_off_t off;

    struct vznncv_lfs1_disk_entry {
        uint8_t type;
        uint8_t elen;
        uint8_t alen;
        uint8_t nlen;
        union {
            struct {
                vznncv_lfs_block_t head;
                vznncv_lfs_size_t size;
            } file;
            vznncv_lfs_block_t dir[2];
        } u;
    } d;
} vznncv_lfs1_entry_t;

typedef struct vznncv_lfs1_dir {
    struct vznncv_lfs1_dir *next;
    vznncv_lfs_block_t pair[2];
    vznncv_lfs_off_t off;

    vznncv_lfs_block_t head[2];
    vznncv_lfs_off_t pos;

    struct vznncv_lfs1_disk_dir {
        uint32_t rev;
        vznncv_lfs_size_t size;
        vznncv_lfs_block_t tail[2];
    } d;
} vznncv_lfs1_dir_t;

typedef struct vznncv_lfs1_superblock {
    vznncv_lfs_off_t off;

    struct vznncv_lfs1_disk_superblock {
        uint8_t type;
        uint8_t elen;
        uint8_t alen;
        uint8_t nlen;
        vznncv_lfs_block_t root[2];
        uint32_t block_size;
        uint32_t block_count;
        uint32_t version;
        char magic[8];
    } d;
} vznncv_lfs1_superblock_t;


/// Low-level wrappers v1->v2 ///
static void vznncv_lfs1_crc(uint32_t *crc, const void *buffer, size_t size) {
    *crc = vznncv_lfs_crc(*crc, buffer, size);
}

static int vznncv_lfs1_bd_read(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_block_t block,
        vznncv_lfs_off_t off, void *buffer, vznncv_lfs_size_t size) {
    // if we ever do more than writes to alternating pairs,
    // this may need to consider pcache
    return vznncv_lfs_bd_read(vznncv_lfs, &vznncv_lfs->pcache, &vznncv_lfs->rcache, size,
            block, off, buffer, size);
}

static int vznncv_lfs1_bd_crc(vznncv_lfs_t *vznncv_lfs, vznncv_lfs_block_t block,
        vznncv_lfs_off_t off, vznncv_lfs_size_t size, uint32_t *crc) {
    for (vznncv_lfs_off_t i = 0; i < size; i++) {
        uint8_t c;
        int err = vznncv_lfs1_bd_read(vznncv_lfs, block, off+i, &c, 1);
        if (err) {
            return err;
        }

        vznncv_lfs1_crc(crc, &c, 1);
    }

    return 0;
}


/// Endian swapping functions ///
static void vznncv_lfs1_dir_fromle32(struct vznncv_lfs1_disk_dir *d) {
    d->rev     = vznncv_lfs_fromle32(d->rev);
    d->size    = vznncv_lfs_fromle32(d->size);
    d->tail[0] = vznncv_lfs_fromle32(d->tail[0]);
    d->tail[1] = vznncv_lfs_fromle32(d->tail[1]);
}

static void vznncv_lfs1_dir_tole32(struct vznncv_lfs1_disk_dir *d) {
    d->rev     = vznncv_lfs_tole32(d->rev);
    d->size    = vznncv_lfs_tole32(d->size);
    d->tail[0] = vznncv_lfs_tole32(d->tail[0]);
    d->tail[1] = vznncv_lfs_tole32(d->tail[1]);
}

static void vznncv_lfs1_entry_fromle32(struct vznncv_lfs1_disk_entry *d) {
    d->u.dir[0] = vznncv_lfs_fromle32(d->u.dir[0]);
    d->u.dir[1] = vznncv_lfs_fromle32(d->u.dir[1]);
}

static void vznncv_lfs1_entry_tole32(struct vznncv_lfs1_disk_entry *d) {
    d->u.dir[0] = vznncv_lfs_tole32(d->u.dir[0]);
    d->u.dir[1] = vznncv_lfs_tole32(d->u.dir[1]);
}

static void vznncv_lfs1_superblock_fromle32(struct vznncv_lfs1_disk_superblock *d) {
    d->root[0]     = vznncv_lfs_fromle32(d->root[0]);
    d->root[1]     = vznncv_lfs_fromle32(d->root[1]);
    d->block_size  = vznncv_lfs_fromle32(d->block_size);
    d->block_count = vznncv_lfs_fromle32(d->block_count);
    d->version     = vznncv_lfs_fromle32(d->version);
}


///// Metadata pair and directory operations ///
static inline vznncv_lfs_size_t vznncv_lfs1_entry_size(const vznncv_lfs1_entry_t *entry) {
    return 4 + entry->d.elen + entry->d.alen + entry->d.nlen;
}

static int vznncv_lfs1_dir_fetch(vznncv_lfs_t *vznncv_lfs,
        vznncv_lfs1_dir_t *dir, const vznncv_lfs_block_t pair[2]) {
    // copy out pair, otherwise may be aliasing dir
    const vznncv_lfs_block_t tpair[2] = {pair[0], pair[1]};
    bool valid = false;

    // check both blocks for the most recent revision
    for (int i = 0; i < 2; i++) {
        struct vznncv_lfs1_disk_dir test;
        int err = vznncv_lfs1_bd_read(vznncv_lfs, tpair[i], 0, &test, sizeof(test));
        vznncv_lfs1_dir_fromle32(&test);
        if (err) {
            if (err == VZNNCV_LFS_ERR_CORRUPT) {
                continue;
            }
            return err;
        }

        if (valid && vznncv_lfs_scmp(test.rev, dir->d.rev) < 0) {
            continue;
        }

        if ((0x7fffffff & test.size) < sizeof(test)+4 ||
            (0x7fffffff & test.size) > vznncv_lfs->cfg->block_size) {
            continue;
        }

        uint32_t crc = 0xffffffff;
        vznncv_lfs1_dir_tole32(&test);
        vznncv_lfs1_crc(&crc, &test, sizeof(test));
        vznncv_lfs1_dir_fromle32(&test);
        err = vznncv_lfs1_bd_crc(vznncv_lfs, tpair[i], sizeof(test),
                (0x7fffffff & test.size) - sizeof(test), &crc);
        if (err) {
            if (err == VZNNCV_LFS_ERR_CORRUPT) {
                continue;
            }
            return err;
        }

        if (crc != 0) {
            continue;
        }

        valid = true;

        // setup dir in case it's valid
        dir->pair[0] = tpair[(i+0) % 2];
        dir->pair[1] = tpair[(i+1) % 2];
        dir->off = sizeof(dir->d);
        dir->d = test;
    }

    if (!valid) {
        VZNNCV_LFS_ERROR("Corrupted dir pair at {0x%"PRIx32", 0x%"PRIx32"}",
                tpair[0], tpair[1]);
        return VZNNCV_LFS_ERR_CORRUPT;
    }

    return 0;
}

static int vznncv_lfs1_dir_next(vznncv_lfs_t *vznncv_lfs, vznncv_lfs1_dir_t *dir, vznncv_lfs1_entry_t *entry) {
    while (dir->off + sizeof(entry->d) > (0x7fffffff & dir->d.size)-4) {
        if (!(0x80000000 & dir->d.size)) {
            entry->off = dir->off;
            return VZNNCV_LFS_ERR_NOENT;
        }

        int err = vznncv_lfs1_dir_fetch(vznncv_lfs, dir, dir->d.tail);
        if (err) {
            return err;
        }

        dir->off = sizeof(dir->d);
        dir->pos += sizeof(dir->d) + 4;
    }

    int err = vznncv_lfs1_bd_read(vznncv_lfs, dir->pair[0], dir->off,
            &entry->d, sizeof(entry->d));
    vznncv_lfs1_entry_fromle32(&entry->d);
    if (err) {
        return err;
    }

    entry->off = dir->off;
    dir->off += vznncv_lfs1_entry_size(entry);
    dir->pos += vznncv_lfs1_entry_size(entry);
    return 0;
}

/// littlefs v1 specific operations ///
int vznncv_lfs1_traverse(vznncv_lfs_t *vznncv_lfs, int (*cb)(void*, vznncv_lfs_block_t), void *data) {
    if (vznncv_lfs_pair_isnull(vznncv_lfs->vznncv_lfs1->root)) {
        return 0;
    }

    // iterate over metadata pairs
    vznncv_lfs1_dir_t dir;
    vznncv_lfs1_entry_t entry;
    vznncv_lfs_block_t cwd[2] = {0, 1};

    while (true) {
        for (int i = 0; i < 2; i++) {
            int err = cb(data, cwd[i]);
            if (err) {
                return err;
            }
        }

        int err = vznncv_lfs1_dir_fetch(vznncv_lfs, &dir, cwd);
        if (err) {
            return err;
        }

        // iterate over contents
        while (dir.off + sizeof(entry.d) <= (0x7fffffff & dir.d.size)-4) {
            err = vznncv_lfs1_bd_read(vznncv_lfs, dir.pair[0], dir.off,
                    &entry.d, sizeof(entry.d));
            vznncv_lfs1_entry_fromle32(&entry.d);
            if (err) {
                return err;
            }

            dir.off += vznncv_lfs1_entry_size(&entry);
            if ((0x70 & entry.d.type) == (0x70 & VZNNCV_LFS1_TYPE_REG)) {
                err = vznncv_lfs_ctz_traverse(vznncv_lfs, NULL, &vznncv_lfs->rcache,
                        entry.d.u.file.head, entry.d.u.file.size, cb, data);
                if (err) {
                    return err;
                }
            }
        }

        // we also need to check if we contain a threaded v2 directory
        vznncv_lfs_mdir_t dir2 = {.split=true, .tail={cwd[0], cwd[1]}};
        while (dir2.split) {
            err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir2, dir2.tail);
            if (err) {
                break;
            }

            for (int i = 0; i < 2; i++) {
                err = cb(data, dir2.pair[i]);
                if (err) {
                    return err;
                }
            }
        }

        cwd[0] = dir.d.tail[0];
        cwd[1] = dir.d.tail[1];

        if (vznncv_lfs_pair_isnull(cwd)) {
            break;
        }
    }

    return 0;
}

static int vznncv_lfs1_moved(vznncv_lfs_t *vznncv_lfs, const void *e) {
    if (vznncv_lfs_pair_isnull(vznncv_lfs->vznncv_lfs1->root)) {
        return 0;
    }

    // skip superblock
    vznncv_lfs1_dir_t cwd;
    int err = vznncv_lfs1_dir_fetch(vznncv_lfs, &cwd, (const vznncv_lfs_block_t[2]){0, 1});
    if (err) {
        return err;
    }

    // iterate over all directory directory entries
    vznncv_lfs1_entry_t entry;
    while (!vznncv_lfs_pair_isnull(cwd.d.tail)) {
        err = vznncv_lfs1_dir_fetch(vznncv_lfs, &cwd, cwd.d.tail);
        if (err) {
            return err;
        }

        while (true) {
            err = vznncv_lfs1_dir_next(vznncv_lfs, &cwd, &entry);
            if (err && err != VZNNCV_LFS_ERR_NOENT) {
                return err;
            }

            if (err == VZNNCV_LFS_ERR_NOENT) {
                break;
            }

            if (!(0x80 & entry.d.type) &&
                 memcmp(&entry.d.u, e, sizeof(entry.d.u)) == 0) {
                return true;
            }
        }
    }

    return false;
}

/// Filesystem operations ///
static int vznncv_lfs1_mount(vznncv_lfs_t *vznncv_lfs, struct vznncv_lfs1 *vznncv_lfs1,
        const struct vznncv_lfs_config *cfg) {
    int err = 0;
    {
        err = vznncv_lfs_init(vznncv_lfs, cfg);
        if (err) {
            return err;
        }

        vznncv_lfs->vznncv_lfs1 = vznncv_lfs1;
        vznncv_lfs->vznncv_lfs1->root[0] = VZNNCV_LFS_BLOCK_NULL;
        vznncv_lfs->vznncv_lfs1->root[1] = VZNNCV_LFS_BLOCK_NULL;

        // setup free lookahead
        vznncv_lfs->free.off = 0;
        vznncv_lfs->free.size = 0;
        vznncv_lfs->free.i = 0;
        vznncv_lfs_alloc_ack(vznncv_lfs);

        // load superblock
        vznncv_lfs1_dir_t dir;
        vznncv_lfs1_superblock_t superblock;
        err = vznncv_lfs1_dir_fetch(vznncv_lfs, &dir, (const vznncv_lfs_block_t[2]){0, 1});
        if (err && err != VZNNCV_LFS_ERR_CORRUPT) {
            goto cleanup;
        }

        if (!err) {
            err = vznncv_lfs1_bd_read(vznncv_lfs, dir.pair[0], sizeof(dir.d),
                    &superblock.d, sizeof(superblock.d));
            vznncv_lfs1_superblock_fromle32(&superblock.d);
            if (err) {
                goto cleanup;
            }

            vznncv_lfs->vznncv_lfs1->root[0] = superblock.d.root[0];
            vznncv_lfs->vznncv_lfs1->root[1] = superblock.d.root[1];
        }

        if (err || memcmp(superblock.d.magic, "littlefs", 8) != 0) {
            VZNNCV_LFS_ERROR("Invalid superblock at {0x%"PRIx32", 0x%"PRIx32"}",
                    0, 1);
            err = VZNNCV_LFS_ERR_CORRUPT;
            goto cleanup;
        }

        uint16_t major_version = (0xffff & (superblock.d.version >> 16));
        uint16_t minor_version = (0xffff & (superblock.d.version >>  0));
        if ((major_version != VZNNCV_LFS1_DISK_VERSION_MAJOR ||
             minor_version > VZNNCV_LFS1_DISK_VERSION_MINOR)) {
            VZNNCV_LFS_ERROR("Invalid version v%d.%d", major_version, minor_version);
            err = VZNNCV_LFS_ERR_INVAL;
            goto cleanup;
        }

        return 0;
    }

cleanup:
    vznncv_lfs_deinit(vznncv_lfs);
    return err;
}

static int vznncv_lfs1_unmount(vznncv_lfs_t *vznncv_lfs) {
    return vznncv_lfs_deinit(vznncv_lfs);
}

/// v1 migration ///
int vznncv_lfs_migrate(vznncv_lfs_t *vznncv_lfs, const struct vznncv_lfs_config *cfg) {
    VZNNCV_LFS_TRACE("vznncv_lfs_migrate(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)vznncv_lfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);
    struct vznncv_lfs1 vznncv_lfs1;
    int err = vznncv_lfs1_mount(vznncv_lfs, &vznncv_lfs1, cfg);
    if (err) {
        VZNNCV_LFS_TRACE("vznncv_lfs_migrate -> %d", err);
        return err;
    }

    {
        // iterate through each directory, copying over entries
        // into new directory
        vznncv_lfs1_dir_t dir1;
        vznncv_lfs_mdir_t dir2;
        dir1.d.tail[0] = vznncv_lfs->vznncv_lfs1->root[0];
        dir1.d.tail[1] = vznncv_lfs->vznncv_lfs1->root[1];
        while (!vznncv_lfs_pair_isnull(dir1.d.tail)) {
            // iterate old dir
            err = vznncv_lfs1_dir_fetch(vznncv_lfs, &dir1, dir1.d.tail);
            if (err) {
                goto cleanup;
            }

            // create new dir and bind as temporary pretend root
            err = vznncv_lfs_dir_alloc(vznncv_lfs, &dir2);
            if (err) {
                goto cleanup;
            }

            dir2.rev = dir1.d.rev;
            dir1.head[0] = dir1.pair[0];
            dir1.head[1] = dir1.pair[1];
            vznncv_lfs->root[0] = dir2.pair[0];
            vznncv_lfs->root[1] = dir2.pair[1];

            err = vznncv_lfs_dir_commit(vznncv_lfs, &dir2, NULL, 0);
            if (err) {
                goto cleanup;
            }

            while (true) {
                vznncv_lfs1_entry_t entry1;
                err = vznncv_lfs1_dir_next(vznncv_lfs, &dir1, &entry1);
                if (err && err != VZNNCV_LFS_ERR_NOENT) {
                    goto cleanup;
                }

                if (err == VZNNCV_LFS_ERR_NOENT) {
                    break;
                }

                // check that entry has not been moved
                if (entry1.d.type & 0x80) {
                    int moved = vznncv_lfs1_moved(vznncv_lfs, &entry1.d.u);
                    if (moved < 0) {
                        err = moved;
                        goto cleanup;
                    }

                    if (moved) {
                        continue;
                    }

                    entry1.d.type &= ~0x80;
                }

                // also fetch name
                char name[VZNNCV_LFS_NAME_MAX+1];
                memset(name, 0, sizeof(name));
                err = vznncv_lfs1_bd_read(vznncv_lfs, dir1.pair[0],
                        entry1.off + 4+entry1.d.elen+entry1.d.alen,
                        name, entry1.d.nlen);
                if (err) {
                    goto cleanup;
                }

                bool isdir = (entry1.d.type == VZNNCV_LFS1_TYPE_DIR);

                // create entry in new dir
                err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir2, vznncv_lfs->root);
                if (err) {
                    goto cleanup;
                }

                uint16_t id;
                err = vznncv_lfs_dir_find(vznncv_lfs, &dir2, &(const char*){name}, &id);
                if (!(err == VZNNCV_LFS_ERR_NOENT && id != 0x3ff)) {
                    err = (err < 0) ? err : VZNNCV_LFS_ERR_EXIST;
                    goto cleanup;
                }

                vznncv_lfs1_entry_tole32(&entry1.d);
                err = vznncv_lfs_dir_commit(vznncv_lfs, &dir2, VZNNCV_LFS_MKATTRS(
                        {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CREATE, id, 0)},
                        {VZNNCV_LFS_MKTAG_IF_ELSE(isdir,
                            VZNNCV_LFS_TYPE_DIR, id, entry1.d.nlen,
                            VZNNCV_LFS_TYPE_REG, id, entry1.d.nlen),
                                name},
                        {VZNNCV_LFS_MKTAG_IF_ELSE(isdir,
                            VZNNCV_LFS_TYPE_DIRSTRUCT, id, sizeof(entry1.d.u),
                            VZNNCV_LFS_TYPE_CTZSTRUCT, id, sizeof(entry1.d.u)),
                                &entry1.d.u}));
                vznncv_lfs1_entry_fromle32(&entry1.d);
                if (err) {
                    goto cleanup;
                }
            }

            if (!vznncv_lfs_pair_isnull(dir1.d.tail)) {
                // find last block and update tail to thread into fs
                err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir2, vznncv_lfs->root);
                if (err) {
                    goto cleanup;
                }

                while (dir2.split) {
                    err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir2, dir2.tail);
                    if (err) {
                        goto cleanup;
                    }
                }

                vznncv_lfs_pair_tole32(dir2.pair);
                err = vznncv_lfs_dir_commit(vznncv_lfs, &dir2, VZNNCV_LFS_MKATTRS(
                        {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_SOFTTAIL, 0x3ff, 8), dir1.d.tail}));
                vznncv_lfs_pair_fromle32(dir2.pair);
                if (err) {
                    goto cleanup;
                }
            }

            // Copy over first block to thread into fs. Unfortunately
            // if this fails there is not much we can do.
            VZNNCV_LFS_DEBUG("Migrating {0x%"PRIx32", 0x%"PRIx32"} "
                        "-> {0x%"PRIx32", 0x%"PRIx32"}",
                    vznncv_lfs->root[0], vznncv_lfs->root[1], dir1.head[0], dir1.head[1]);

            err = vznncv_lfs_bd_erase(vznncv_lfs, dir1.head[1]);
            if (err) {
                goto cleanup;
            }

            err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir2, vznncv_lfs->root);
            if (err) {
                goto cleanup;
            }

            for (vznncv_lfs_off_t i = 0; i < dir2.off; i++) {
                uint8_t dat;
                err = vznncv_lfs_bd_read(vznncv_lfs,
                        NULL, &vznncv_lfs->rcache, dir2.off,
                        dir2.pair[0], i, &dat, 1);
                if (err) {
                    goto cleanup;
                }

                err = vznncv_lfs_bd_prog(vznncv_lfs,
                        &vznncv_lfs->pcache, &vznncv_lfs->rcache, true,
                        dir1.head[1], i, &dat, 1);
                if (err) {
                    goto cleanup;
                }
            }

            err = vznncv_lfs_bd_flush(vznncv_lfs, &vznncv_lfs->pcache, &vznncv_lfs->rcache, true);
            if (err) {
                goto cleanup;
            }
        }

        // Create new superblock. This marks a successful migration!
        err = vznncv_lfs1_dir_fetch(vznncv_lfs, &dir1, (const vznncv_lfs_block_t[2]){0, 1});
        if (err) {
            goto cleanup;
        }

        dir2.pair[0] = dir1.pair[0];
        dir2.pair[1] = dir1.pair[1];
        dir2.rev = dir1.d.rev;
        dir2.off = sizeof(dir2.rev);
        dir2.etag = 0xffffffff;
        dir2.count = 0;
        dir2.tail[0] = vznncv_lfs->vznncv_lfs1->root[0];
        dir2.tail[1] = vznncv_lfs->vznncv_lfs1->root[1];
        dir2.erased = false;
        dir2.split = true;

        vznncv_lfs_superblock_t superblock = {
            .version     = VZNNCV_LFS_DISK_VERSION,
            .block_size  = vznncv_lfs->cfg->block_size,
            .block_count = vznncv_lfs->cfg->block_count,
            .name_max    = vznncv_lfs->name_max,
            .file_max    = vznncv_lfs->file_max,
            .attr_max    = vznncv_lfs->attr_max,
        };

        vznncv_lfs_superblock_tole32(&superblock);
        err = vznncv_lfs_dir_commit(vznncv_lfs, &dir2, VZNNCV_LFS_MKATTRS(
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_CREATE, 0, 0)},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_SUPERBLOCK, 0, 8), "littlefs"},
                {VZNNCV_LFS_MKTAG(VZNNCV_LFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock}));
        if (err) {
            goto cleanup;
        }

        // sanity check that fetch works
        err = vznncv_lfs_dir_fetch(vznncv_lfs, &dir2, (const vznncv_lfs_block_t[2]){0, 1});
        if (err) {
            goto cleanup;
        }

        // force compaction to prevent accidentally mounting v1
        dir2.erased = false;
        err = vznncv_lfs_dir_commit(vznncv_lfs, &dir2, NULL, 0);
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    vznncv_lfs1_unmount(vznncv_lfs);
    VZNNCV_LFS_TRACE("vznncv_lfs_migrate -> %d", err);
    return err;
}

#endif

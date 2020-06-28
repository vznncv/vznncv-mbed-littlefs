#include "greentea-client/test_env.h"
#include "mbed.h"
#include "mbed_mem_trace.h"
#include "unity.h"
#include "utest.h"
#include <memory>

#include "HeapBlockDevice.h"
#include "ProfilingBlockDevice.h"

#include "mbed_trace.h"

#include "vznncv_mbed_lfs.h"

using std::make_unique;

using namespace utest::v1;
using namespace vznncv;

//--------------------------------
// Helper resources and functions
//--------------------------------
#define WB_FLAG (O_WRONLY | O_CREAT | O_TRUNC)
#define RB_FLAG (O_RDONLY)

#define BD_ROOT_DIR "sd"
#define BD_BLOCK_SIZE 128
#define BD_BLOCK_NUM 96
static HeapBlockDevice heap_bd(BD_BLOCK_SIZE *BD_BLOCK_NUM, BD_BLOCK_SIZE);
static ProfilingBlockDevice prof_bd(&heap_bd);

static int clear_block_devices()
{
    // cleanup heap block device
    uint8_t buf[BD_BLOCK_SIZE];
    heap_bd.init();
    memset(buf, 0, sizeof(buf));
    for (size_t i = 0; i < heap_bd.size(); i += BD_BLOCK_SIZE) {
        heap_bd.erase(i, BD_BLOCK_SIZE);
        heap_bd.program(buf, i, BD_BLOCK_SIZE);
    }
    heap_bd.deinit();
    // cleanup profiling block device counts
    prof_bd.reset();
    return 0;
}

static int write_test_data(const char *path, const void *data, size_t len)
{
    int f;
    int res;
    int write_res;

    f = open(path, WB_FLAG);
    if (f < 0) {
        return -1;
    }

    write_res = write(f, data, len);
    if (write_res != len) {
        return -2;
    }

    res = close(f);
    if (res) {
        return -3;
    }

    return write_res;
}

static int read_test_data(const char *path, void *buf, size_t buf_size)
{
    int f;
    int res;
    int read_res;

    f = open(path, RB_FLAG);
    if (f < 0) {
        return -1;
    }

    read_res = read(f, buf, buf_size);
    if (read_res < 0) {
        return -2;
    }

    res = close(f);
    if (res) {
        return -3;
    }

    return read_res;
}

//--------------------------------
// test setup functions
//--------------------------------

static utest::v1::status_t app_test_setup_handler(const size_t number_of_cases)
{
    return greentea_test_setup_handler(number_of_cases);
}

static utest::v1::status_t app_case_setup_handler(const Case *const source, const size_t index_of_case)
{
    return greentea_case_setup_handler(source, index_of_case);
}

static utest::v1::status_t app_case_teardown_handler(const Case *const source, const size_t passed, const size_t failed, const failure_t failure)
{
    return greentea_case_teardown_handler(source, passed, failed, failure);
}

static void app_test_teardown_handler(const size_t passed, const size_t failed, const failure_t failure)
{
    return greentea_test_teardown_handler(passed, failed, failure);
}

//--------------------------------
// helper unity shortcuts
//--------------------------------

#define ASSERT_SUCCESS(expr)                                                             \
    do {                                                                                 \
        int err = expr;                                                                  \
        UNITY_TEST_ASSERT(!err, __LINE__, " Expression " #expr " is evaluated to false") \
        if (err) {                                                                       \
            return;                                                                      \
        }                                                                                \
    } while (0);

#define ASSERT_GTE_ZERO(expr)                                                                      \
    do {                                                                                           \
        int err = expr;                                                                            \
        UNITY_TEST_ASSERT(err >= 0, __LINE__, " Expression " #expr " is evaluated to as negative") \
        if (err < 0) {                                                                             \
            return;                                                                                \
        }                                                                                          \
    } while (0);

//--------------------------------
// test functions
//--------------------------------

/**
 * Check littlefs logs read/match overhead operations with large block size.
 */

/**
 * Check file system speed degradation after files creation and deletion.
 */
static int measure_bd_usage_after_dummy_operations(FileSystem *fs, const size_t test_file_size, const size_t dummy_file_op_num, size_t *read_size_before_changes, size_t *read_size_after_changnes)
{
    int err;
    int res;
    int f;

    // clear and format block device
    clear_block_devices();
    err = fs->reformat(&prof_bd);
    if (err) {
        return -1;
    }

    // prepare buffer to write/read data
    size_t read_buf_size = test_file_size + 1;
    size_t write_buf_size = test_file_size;
    auto read_content_buf = make_unique<char[]>(read_buf_size);
    auto write_content_buf = make_unique<char[]>(write_buf_size);
    memset(write_content_buf.get(), 'X', write_buf_size);

    // create helper paths
    auto basedir_buf = make_unique<char[]>(64);
    sprintf(basedir_buf.get(), "/%s/test_dir", BD_ROOT_DIR);
    auto basefile_buf = make_unique<char[]>(64);
    sprintf(basefile_buf.get(), "%s/base.txt", basedir_buf.get());
    auto tempfile_buf = make_unique<char[]>(64);
    sprintf(tempfile_buf.get(), "%s/tmp.txt", basedir_buf.get());

    // create test directory and test file
    err = mkdir(basedir_buf.get(), 0777);
    if (err) {
        return -2;
    }
    res = write_test_data(basefile_buf.get(), write_content_buf.get(), test_file_size);
    if (res != test_file_size) {
        return -3;
    }

    // measure number of read operations to read file content
    prof_bd.reset();
    res = read_test_data(basefile_buf.get(), read_content_buf.get(), read_buf_size);
    if (res != test_file_size) {
        return -4;
    }
    *read_size_before_changes = prof_bd.get_read_count();

    // write/delete dummy file
    for (int i = 0; i < dummy_file_op_num; i++) {
        // create temporary files
        res = write_test_data(tempfile_buf.get(), write_content_buf.get(), test_file_size);
        if (res != test_file_size) {
            return -5;
        }
        // remove temporary files
        res = remove(tempfile_buf.get());
        if (res) {
            return -6;
        }
    }

    // measure number of read operations to read file content
    prof_bd.reset();
    res = read_test_data(basefile_buf.get(), read_content_buf.get(), read_buf_size);
    if (res != test_file_size) {
        return -7;
    }
    *read_size_after_changnes = prof_bd.get_read_count();

    err = fs->unmount();
    if (err) {
        return -8;
    }

    return 0;
}

static void test_lfs_logs_overdead()
{
    int err;
    const size_t lfs_block_size = BD_BLOCK_SIZE * 8;
    const size_t test_file_size = lfs_block_size - 64;
    const size_t dummy_file_op_num = 4;

    size_t read_size_before_changes;
    size_t read_size_after_changnes;

    // prepare file system
    auto fs = make_unique<FMLittleFileSystem2>(BD_ROOT_DIR, 2, 2, lfs_block_size);

    // measure performance
    err = measure_bd_usage_after_dummy_operations(fs.get(), test_file_size, dummy_file_op_num, &read_size_before_changes, &read_size_after_changnes);
    ASSERT_SUCCESS(err);

    int logs_grow_overhead = (int)read_size_after_changnes - (int)read_size_before_changes;

    TEST_ASSERT(logs_grow_overhead < 2 * BD_BLOCK_SIZE);
}

// test cases description
#define SimpleCase(test_fun) Case(#test_fun, app_case_setup_handler, test_fun, app_case_teardown_handler, greentea_case_failure_continue_handler)
static Case cases[] = {
    SimpleCase(test_lfs_logs_overdead)

};
static Specification specification(app_test_setup_handler, cases, app_test_teardown_handler);

// Entry point into the tests
int main()
{
    // configure mbed_trace
    mbed_trace_config_set(TRACE_MODE_PLAIN | TRACE_ACTIVE_LEVEL_ALL);
    mbed_trace_init();

    // host handshake
    // note: should be invoked here or in the test_setup_handler
    GREENTEA_SETUP(40, "default_auto");
    // run tests
    return !Harness::run(specification);
}

#include "greentea-client/test_env.h"
#include "mbed.h"
#include "mbed_mem_trace.h"
#include "unity.h"
#include "utest.h"
#include <memory>

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
static HeapBlockDevice bd(12 * 1024, BD_BLOCK_SIZE);

static int init_block_device()
{
    // cleanup block device
    uint8_t buf[BD_BLOCK_SIZE];
    bd.init();
    memset(buf, 0, sizeof(buf));
    for (size_t i = 0; i < bd.size(); i += BD_BLOCK_SIZE) {
        bd.erase(i, BD_BLOCK_SIZE);
        bd.program(buf, i, BD_BLOCK_SIZE);
    }
    bd.deinit();
    return 0;
}

static int test_trace_memory_alloc_operation_count = 0;
static int test_trace_memory_dealloc_operations_count = 0;

static void test_trace_memory_cb(uint8_t op, void *res, void *caller, ...)
{
    void *ptr;

    va_list args;
    va_start(args, caller);
    switch (op) {
    case MBED_MEM_TRACE_MALLOC:
        va_arg(args, size_t); // size
        test_trace_memory_alloc_operation_count++;
        break;
    case MBED_MEM_TRACE_REALLOC:
        ptr = va_arg(args, void *); // original ptr
        va_arg(args, size_t); // size
        test_trace_memory_alloc_operation_count++;
        if (ptr != nullptr) {
            test_trace_memory_dealloc_operations_count++;
        }
        break;
    case MBED_MEM_TRACE_CALLOC:
        va_arg(args, size_t); // num
        va_arg(args, size_t); // size
        test_trace_memory_alloc_operation_count++;
        break;
    case MBED_MEM_TRACE_FREE:
        va_arg(args, void *); // ptr
        test_trace_memory_dealloc_operations_count++;
        break;
    default:
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, MBED_ERROR_INVALID_OPERATION), "Unknown memory operation code");
    }
    va_end(args);
}

static int test_trace_memory_reset()
{
    test_trace_memory_alloc_operation_count = 0;
    test_trace_memory_dealloc_operations_count = 0;
    return 0;
}

static int test_tarce_memory_get(int *alloc_count, int *dealloc_count)
{
    *alloc_count = test_trace_memory_alloc_operation_count;
    *dealloc_count = test_trace_memory_dealloc_operations_count;
    return 0;
}

static int test_trace_memory_init()
{
    static_assert(MBED_MEM_TRACING_ENABLED, "Mbed memory tracing isn't enabled");
    mbed_mem_trace_set_callback(test_trace_memory_cb);
    test_trace_memory_reset();
}

//--------------------------------
// test setup functions
//--------------------------------

static utest::v1::status_t app_test_setup_handler(const size_t number_of_cases)
{
    test_trace_memory_init();
    return greentea_test_setup_handler(number_of_cases);
}

static int clean_test_bufs();

static utest::v1::status_t app_case_setup_handler(const Case *const source, const size_t index_of_case)
{
    init_block_device();
    test_trace_memory_reset();
    clean_test_bufs();
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

static char path_buf[64];
static char basepath_buf[64];
static char content_buf[32];
static size_t content_buf_size = sizeof(content_buf);
static char filename_buf[32];

static int clean_test_bufs()
{
    memset(path_buf, 0, sizeof(path_buf));
    memset(basepath_buf, 0, sizeof(basepath_buf));
    memset(content_buf, 0, sizeof(content_buf));
    memset(filename_buf, 0, sizeof(filename_buf));
}

static void test_file_operations()
{
    int err;
    const char *text = "abc123";
    ssize_t res;
    int f;
    int alloc_count, dealloc_count;

    // prepare file system
    auto fs = make_unique<FMLittleFileSystem2>(BD_ROOT_DIR, 2, 2, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE);
    ASSERT_SUCCESS(fs->reformat(&bd));

    // create simple file
    test_trace_memory_reset();
    sprintf(path_buf, "/%s/%s", BD_ROOT_DIR, "file.bin");
    f = open(path_buf, WB_FLAG);
    ASSERT_GTE_ZERO(f);
    res = write(f, text, strlen(text));
    ASSERT_GTE_ZERO(res)
    TEST_ASSERT_EQUAL(res, strlen(text));
    ASSERT_SUCCESS(close(f));
    // check memory operations
    test_tarce_memory_get(&alloc_count, &dealloc_count);
    TEST_ASSERT_EQUAL(0, alloc_count);
    TEST_ASSERT_EQUAL(0, dealloc_count);

    // read file
    test_trace_memory_reset();
    f = open(path_buf, RB_FLAG);
    ASSERT_GTE_ZERO(f);
    res = read(f, content_buf, sizeof(content_buf));
    ASSERT_GTE_ZERO(res);
    TEST_ASSERT_EQUAL(res, strlen(text));
    TEST_ASSERT_EQUAL_STRING_LEN(text, content_buf, strlen(text));
    ASSERT_SUCCESS(close(f));
    // check memory operations
    test_tarce_memory_get(&alloc_count, &dealloc_count);
    TEST_ASSERT_EQUAL(0, alloc_count);
    TEST_ASSERT_EQUAL(0, dealloc_count);

    // unmount file system
    ASSERT_SUCCESS(fs->unmount());
}

static void test_file_limit()
{
    int name_cnt = 0;
    auto build_file_path = [&]() {
        sprintf(filename_buf, "file_%i", name_cnt++);
        sprintf(path_buf, "/%s/%s", BD_ROOT_DIR, filename_buf);
        return path_buf;
    };

    const char *path;
    const size_t max_file_num = 2;
    int f;
    int f_ids[max_file_num];
    int file_cnt;

    int alloc_count, dealloc_count;

    // prepare file system
    auto fs = make_unique<FMLittleFileSystem2>(BD_ROOT_DIR, max_file_num, 2, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE);
    ASSERT_SUCCESS(fs->reformat(&bd));

    // allocate all aviable files
    test_trace_memory_reset();
    file_cnt = 0;
    while (file_cnt < max_file_num) {
        path = build_file_path();
        f = open(path, WB_FLAG);
        ASSERT_GTE_ZERO(f);
        f_ids[file_cnt++] = f;
    }
    // check that new file allocation isn't possible
    path = build_file_path();
    f = open(path, WB_FLAG);
    TEST_ASSERT_EQUAL(-1, f);
    // close one file and try to allocate file again
    ASSERT_SUCCESS(close(f_ids[--file_cnt]));
    f = open(path, WB_FLAG);
    ASSERT_GTE_ZERO(f);
    f_ids[file_cnt++] = f;
    // close all files
    while (file_cnt > 0) {
        ASSERT_SUCCESS(close(f_ids[--file_cnt]));
    }

    // check memory operations
    test_tarce_memory_get(&alloc_count, &dealloc_count);
    TEST_ASSERT_EQUAL(0, alloc_count);
    TEST_ASSERT_EQUAL(0, dealloc_count);

    // unmount file system
    ASSERT_SUCCESS(fs->unmount());
}

static void test_directory_operations()
{
    int f;
    int res;
    struct dirent *dir_ent;
    DIR *d;
    int alloc_count, dealloc_count;

    // prepare file system
    auto fs = make_unique<FMLittleFileSystem2>(BD_ROOT_DIR, 2, 2, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE);
    ASSERT_SUCCESS(fs->reformat(&bd));

    // create test directory and fill it
    test_trace_memory_reset();
    sprintf(basepath_buf, "/%s/%s", BD_ROOT_DIR, "test_dir");
    ASSERT_SUCCESS(mkdir(basepath_buf, 0777));
    // add subdirectory
    sprintf(path_buf, "%s/%s", basepath_buf, "subdir");
    ASSERT_SUCCESS(mkdir(path_buf, 0777));
    // add file
    sprintf(path_buf, "%s/%s", basepath_buf, "file.bin");
    f = open(path_buf, WB_FLAG);
    ASSERT_GTE_ZERO(f);
    res = write(f, "123", 3);
    ASSERT_GTE_ZERO(res);
    ASSERT_SUCCESS(close(f));
    // check memory operations
    test_tarce_memory_get(&alloc_count, &dealloc_count);
    TEST_ASSERT_EQUAL(0, alloc_count);
    TEST_ASSERT_EQUAL(0, dealloc_count);

    // read directory content
    test_trace_memory_reset();
    d = opendir(basepath_buf);
    TEST_ASSERT_NOT_NULL(d);
    int dir_file_cnt = 0;
    int dir_subdir_cnt = 0;
    int dir_other_cnt = 0;
    while ((dir_ent = readdir(d))) {
        if (strcmp(dir_ent->d_name, ".") == 0 || strcmp(dir_ent->d_name, "..") == 0) {
            continue;
        } else if (strcmp(dir_ent->d_name, "file.bin") == 0 && dir_ent->d_type == DT_REG) {
            dir_file_cnt++;
        } else if (strcmp(dir_ent->d_name, "subdir") == 0 && dir_ent->d_type == DT_DIR) {
            dir_subdir_cnt++;
        } else {
            dir_other_cnt++;
        }
    }
    TEST_ASSERT_EQUAL(1, dir_file_cnt);
    TEST_ASSERT_EQUAL(1, dir_subdir_cnt);
    TEST_ASSERT_EQUAL(0, dir_other_cnt);
    ASSERT_SUCCESS(closedir(d));
    // check memory operations
    test_tarce_memory_get(&alloc_count, &dealloc_count);
    TEST_ASSERT_EQUAL(0, alloc_count);
    TEST_ASSERT_EQUAL(0, dealloc_count);

    // unmount file system
    ASSERT_SUCCESS(fs->unmount());
}

static void test_directory_limit()
{
    int err;
    auto build_dir_path = [&](int i) {
        sprintf(basepath_buf, "dir_%i", i++);
        sprintf(path_buf, "/%s/%s", BD_ROOT_DIR, basepath_buf);
        return path_buf;
    };

    auto create_test_dir = [&](int i) {
        const char *path = build_dir_path(i);
        int err = mkdir(path, 0777);
        if (err) {
            return err;
        }
        char sub_path[64];
        sprintf(sub_path, "%s/%s", path, "subdir");
        err = mkdir(sub_path, 0777);
        if (err) {
            return err;
        }
        sprintf(sub_path, "%s/%s", path, "test_file");
        int f = open(sub_path, WB_FLAG);
        write(f, "abc", 3);
        err = close(f);
        return err;
    };

    const char *path;
    const size_t max_dir_num = 2;
    DIR *d;
    DIR *d_ids[max_dir_num];
    int dir_cnt;
    int alloc_count, dealloc_count;

    // prepare file system
    auto fs = make_unique<FMLittleFileSystem2>(BD_ROOT_DIR, 1, max_dir_num, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE, BD_BLOCK_SIZE);
    ASSERT_SUCCESS(fs->reformat(&bd));

    test_trace_memory_reset();

    // create test directories
    for (int i = 0; i < 4; i++) {
        ASSERT_SUCCESS(create_test_dir(i));
    }
    // open directories
    dir_cnt = 0;
    while (dir_cnt < max_dir_num) {
        path = build_dir_path(dir_cnt);
        d = opendir(path);
        TEST_ASSERT_NOT_NULL(d);
        d_ids[dir_cnt++] = d;
    }
    // check that new directory cannot be opened
    path = build_dir_path(3);
    d = opendir(path);
    TEST_ASSERT_NULL(d);
    // close one directory and try to open directory again
    ASSERT_SUCCESS(closedir(d_ids[--dir_cnt]));
    d = opendir(path);
    TEST_ASSERT_NOT_NULL(d);
    d_ids[dir_cnt++] = d;
    // close directories
    while (dir_cnt > 0) {
        ASSERT_SUCCESS(closedir(d_ids[--dir_cnt]));
    }

    // check memory operations
    test_tarce_memory_get(&alloc_count, &dealloc_count);
    TEST_ASSERT_EQUAL(0, alloc_count);
    TEST_ASSERT_EQUAL(0, dealloc_count);

    // unmount file system
    ASSERT_SUCCESS(fs->unmount());
}

// test cases description
#define SimpleCase(test_fun) Case(#test_fun, app_case_setup_handler, test_fun, app_case_teardown_handler, greentea_case_failure_continue_handler)
static Case cases[] = {
    SimpleCase(test_file_operations),
    SimpleCase(test_file_limit),
    SimpleCase(test_directory_operations),
    SimpleCase(test_directory_limit),

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

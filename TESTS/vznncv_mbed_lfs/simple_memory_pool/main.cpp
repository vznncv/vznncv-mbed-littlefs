#include "greentea-client/test_env.h"
#include "mbed.h"
#include "unity/unity.h"
#include "utest/utest.h"

#include "vznncv_mbed_lfs_simple_memory_pool.h"

using namespace vznncv;
using namespace utest::v1;

template <size_t buf_size = 10>
class DemoObj {
public:
    uint8_t buf[buf_size];
    int i;
    char c;

    DemoObj()
    {
        memset(buf, 0, buf_size);
        i = 0;
        c = 'T';
    }
    virtual ~DemoObj()
    {
    }

    virtual int set_test_data()
    {
        // set data
        i = 42;
        c = 'E';
        for (size_t j = 0; j < buf_size; j++) {
            buf[j] = 'F';
        }
        return 0;
    }

    virtual int validate_test_data()
    {
        int err = 0;

        // check data
        if (i != 42) {
            err--;
        }
        if (c != 'E') {
            err--;
        }
        for (size_t j = 0; j < buf_size; j++) {
            if (buf[j] != 'F') {
                err--;
            }
        }
        if (err) {
            TEST_FAIL_MESSAGE("DemoObj memory error");
        }
        return err;
    }

    virtual int validate_memory()
    {
        set_test_data();
        return validate_test_data();
    }
};

/**
 * Test simple single allocation/deallocation.
 */
static void test_simple_usage()
{
    const size_t obj_size = sizeof(DemoObj<>);
    const size_t num_obj = 10;
    DemoObj<> *obj;
    DemoObj<> *obj_mem;
    SimpleMemoryPool<DemoObj<>> mem_pool(num_obj);

    for (int i = 0; i < 4; i++) {
        // allocate block
        obj_mem = mem_pool.allocate();
        TEST_ASSERT_NOT_NULL(obj_mem);
        if (obj_mem == nullptr) {
            continue;
        }
        // check that block can be used for a memory
        obj = new (obj_mem) DemoObj<>();
        TEST_ASSERT_EQUAL(0, obj->validate_memory());
        // release memory
        obj->~DemoObj();
        mem_pool.deallocate(obj_mem);
    }
}

static int next_rand(int *state)
{
    return *state = *state * 1103515245 + 12345;
}

template <typename T>
static void shuffle_array(T **array, size_t size, int *state)
{
    for (int i = 0; i < size; i++) {
        int i1 = next_rand(state) % size;
        int i2 = next_rand(state) % size;
        T *elem = array[i1];
        array[i1] = array[i2];
        array[i2] = elem;
    }
}

/**
 * Complex usage with multiple object allocation/deallocation.
 */
static void test_complex_usage()
{
    typedef DemoObj<8> TestDemoObj;

    const size_t obj_size = sizeof(TestDemoObj);
    const size_t max_objs = 10;
    TestDemoObj *allocated_objects[max_objs] = {};
    TestDemoObj *obj = nullptr;
    void *raw_data = nullptr;
    size_t obj_count = 0;
    int rand_state;
    int mem_actions[] = { 5, -2, 9, -3, 5, -5 };
    size_t mem_actions_num = sizeof(mem_actions) / sizeof(int);

    SimpleMemoryPool<TestDemoObj> mem_pool(max_objs);

    for (size_t i = 0; i < mem_actions_num; i++) {
        int mem_action = mem_actions[i];
        if (mem_action > 0) {
            // allocate objects
            for (int j = 0; j < mem_action; j++) {
                raw_data = mem_pool.allocate();
                // check allocate result
                if (obj_count >= max_objs) {
                    TEST_ASSERT_NULL(raw_data);
                } else {
                    TEST_ASSERT_NOT_NULL(raw_data);
                }
                if (raw_data == nullptr || obj_count >= max_objs) {
                    continue;
                }
                // validate allocated memory block
                memset(raw_data, 0, obj_size);
                obj = new (raw_data) TestDemoObj();
                TEST_ASSERT_EQUAL(0, obj->set_test_data());
                TEST_ASSERT_EQUAL(0, obj->validate_test_data());
                // push object to stack
                allocated_objects[obj_count++] = obj;
            }
        } else {
            // deallocate objects
            for (int j = 0; j < -mem_action; j++) {
                if (obj_count <= 0) {
                    continue;
                }
                obj = allocated_objects[--obj_count];
                TEST_ASSERT_EQUAL(0, obj->validate_test_data());
                obj->~DemoObj();
                mem_pool.deallocate(obj);
            }
        }
        // shuffle objects
        shuffle_array(allocated_objects, obj_count, &rand_state);
    }
    // deallocate other objects
    while (obj_count > 0) {
        obj = allocated_objects[obj_count--];
        TEST_ASSERT_EQUAL(0, obj->validate_test_data());
        obj->~DemoObj();
        mem_pool.deallocate(obj);
    }
}

struct user_t {
    int id;
    void *data;

    static int user_init(user_t *obj, bool use_flag)
    {
        obj->data = new char[10];
        strcpy((char *)(obj->data), "user");
        obj->id = 42;
        return 0;
    }

    static int user_deinit(user_t *obj, bool use_flag)
    {
        delete[](char *) obj->data;
        obj->data = nullptr;
        obj->id = 0;
        return 0;
    }
};

static void test_process_callback()
{
    int err;
    size_t max_objs = 4;
    user_t *obj;
    SimpleMemoryPool<user_t> mem_pool(max_objs);

    err = mem_pool.process_blocks(callback(user_t::user_init));
    TEST_ASSERT_EQUAL(0, err);

    obj = mem_pool.allocate();
    TEST_ASSERT_NOT_NULL(obj);
    TEST_ASSERT_EQUAL_STRING("user", obj->data);
    TEST_ASSERT_EQUAL(42, obj->id);

    err = mem_pool.process_blocks(callback(user_t::user_deinit));
    TEST_ASSERT_EQUAL(0, err);

    TEST_ASSERT_NULL(obj->data);
    TEST_ASSERT_EQUAL(0, obj->id);

    mem_pool.deallocate(obj);
}

// test cases description
#define SimpleTestCase(test_fun) Case(#test_fun, test_fun, greentea_case_failure_continue_handler)
static Case cases[] = {
    SimpleTestCase(test_simple_usage),
    SimpleTestCase(test_complex_usage),
    SimpleTestCase(test_process_callback)
};
static Specification specification(greentea_test_setup_handler, cases, greentea_test_teardown_handler);

// tests entry point
int main()
{
    // host handshake
    // note: should be invoked here or in the test_setup_handler
    GREENTEA_SETUP(20, "default_auto");
    // run tests
    return !Harness::run(specification);
}

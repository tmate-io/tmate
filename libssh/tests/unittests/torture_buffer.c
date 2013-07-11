#define LIBSSH_STATIC

#include "torture.h"
#define DEBUG_BUFFER
#include "buffer.c"

#define LIMIT (8*1024*1024)

static void setup(void **state) {
    ssh_buffer buffer;
    buffer = ssh_buffer_new();
    *state = (void *) buffer;
}

static void teardown(void **state) {
    ssh_buffer_free(*state);
}

/*
 * Test if the continuously growing buffer size never exceeds 2 time its
 * real capacity
 */
static void torture_growing_buffer(void **state) {
  ssh_buffer buffer = *state;
  int i;

  for(i=0;i<LIMIT;++i){
    buffer_add_data(buffer,"A",1);
    if(buffer->used >= 128){
      if(buffer_get_rest_len(buffer) * 2 < buffer->allocated){
        assert_true(buffer_get_rest_len(buffer) * 2 >= buffer->allocated);
      }
    }
  }
}

/*
 * Test if the continuously growing buffer size never exceeds 2 time its
 * real capacity, when we remove 1 byte after each call (sliding window)
 */
static void torture_growing_buffer_shifting(void **state) {
  ssh_buffer buffer = *state;
  int i;
  unsigned char c;
  for(i=0; i<1024;++i){
    buffer_add_data(buffer,"S",1);
  }
  for(i=0;i<LIMIT;++i){
    buffer_get_u8(buffer,&c);
    buffer_add_data(buffer,"A",1);
    if(buffer->used >= 128){
      if(buffer_get_rest_len(buffer) * 4 < buffer->allocated){
        assert_true(buffer_get_rest_len(buffer) * 4 >= buffer->allocated);
        return;
      }
    }
  }
}

/*
 * Test the behavior of buffer_prepend_data
 */
static void torture_buffer_prepend(void **state) {
  ssh_buffer buffer = *state;
  uint32_t v;
  buffer_add_data(buffer,"abcdef",6);
  buffer_prepend_data(buffer,"xyz",3);
  assert_int_equal(buffer_get_rest_len(buffer),9);
  assert_memory_equal(buffer_get_rest(buffer),  "xyzabcdef", 9);

  /* Now remove 4 bytes and see if we can replace them */
  buffer_get_u32(buffer,&v);
  assert_int_equal(buffer_get_rest_len(buffer),5);
  assert_memory_equal(buffer_get_rest(buffer), "bcdef", 5);

  buffer_prepend_data(buffer,"aris",4);
  assert_int_equal(buffer_get_rest_len(buffer),9);
  assert_memory_equal(buffer_get_rest(buffer), "arisbcdef", 9);

  /* same thing but we add 5 bytes now */
  buffer_get_u32(buffer,&v);
  assert_int_equal(buffer_get_rest_len(buffer),5);
  assert_memory_equal(buffer_get_rest(buffer), "bcdef", 5);

  buffer_prepend_data(buffer,"12345",5);
  assert_int_equal(buffer_get_rest_len(buffer),10);
  assert_memory_equal(buffer_get_rest(buffer), "12345bcdef", 10);
}

/*
 * Test the behavior of buffer_get_ssh_string with invalid data
 */
static void torture_buffer_get_ssh_string(void **state) {
  ssh_buffer buffer;
  int i,j,k,l, rc;
  /* some values that can go wrong */
  uint32_t values[] = {0xffffffff, 0xfffffffe, 0xfffffffc, 0xffffff00,
      0x80000000, 0x80000004, 0x7fffffff};
  char data[128];
  (void)state;
  memset(data,'X',sizeof(data));
  for(i=0; i < (int)(sizeof(values)/sizeof(values[0]));++i){
    for(j=0; j< (int)sizeof(data);++j){
      for(k=1;k<5;++k){
        buffer=buffer_new();
        assert_non_null(buffer);

        for(l=0;l<k;++l){
          rc = buffer_add_u32(buffer,htonl(values[i]));
          assert_int_equal(rc, 0);
        }
        rc = buffer_add_data(buffer,data,j);
        assert_int_equal(rc, 0);
        for(l=0;l<k;++l){
          ssh_string str = buffer_get_ssh_string(buffer);
          assert_null(str);
          ssh_string_free(str);
        }
        buffer_free(buffer);
      }
    }
  }
}



int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_growing_buffer, setup, teardown),
        unit_test_setup_teardown(torture_growing_buffer_shifting, setup, teardown),
        unit_test_setup_teardown(torture_buffer_prepend, setup, teardown),
        unit_test(torture_buffer_get_ssh_string),
    };

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}

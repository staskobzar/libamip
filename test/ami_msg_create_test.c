#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_test (void **state)
{
  (void) *state;
  assert_int_equal(0, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test (test_test),
  };
  return cmocka_run_group_tests_name("Create AMI package tests.", tests, NULL, NULL);
}

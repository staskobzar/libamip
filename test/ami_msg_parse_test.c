#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "amip.h"

static void test_test (void **state)
{
  (void) *state;
  assert_int_equal(dummy(), 1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test (test_test),
  };
  return cmocka_run_group_tests_name("Parse AMI package tests.", tests, NULL, NULL);
}

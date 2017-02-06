#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "amip.h"

int main(void)
{
  const struct CMUnitTest tests[] = {
    //cmocka_unit_test (test_funk_name),
  };
  return cmocka_run_group_tests_name("Parse AMI package tests.", tests, NULL, NULL);
}

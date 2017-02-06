#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "amip.h"

static void create_pack_funk (void **state)
{
  (void) *state;

  struct sbuf pack_str;

  AMIPacket *pack = (AMIPacket*) XMALLOC(sizeof(AMIPacket));

  amipack_init (pack, AMI_ACTION);
  amipack_append (pack, Action, "CoreStatus");
  assert_int_equal (pack->size, 1);

  amipack_to_str(pack, &pack_str);
  amipack_destroy (pack);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test (create_pack_funk),
  };
  return cmocka_run_group_tests_name("Create AMI package tests.", tests, NULL, NULL);
}

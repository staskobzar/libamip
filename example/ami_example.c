#include <stdio.h>
#include <amip.h>

int main(int argc, const char *argv[])
{
  struct str *sp, *hdr;
  // initialize AMI packet structure
  AMIPacket *pack = amipack_init();

  printf("== Example of amip lib usage ==\n");

  // Set AMI packet type to Action
  amipack_type(pack, AMI_ACTION);

  // Add Action header with value "CoreStatus"
  amipack_append(pack, Action, "CoreStatus");
  // Add ActionID header
  amipack_append(pack, ActionID, "e819a1d8-02cf-4f66-be24-5d7cedfa462a");
  // Convert AMI packet to string structure
  sp = amipack_to_str(pack);

  // print packet as string
  printf("--- created packet ---\n");
  printf("%.*s", (int)sp->len, sp->buf);
  // clean memory
  amipack_destroy(pack);

  printf("--- parse packet ---\n");
  // parse string to AMI pack structure
  pack = amiparse_pack(sp->buf);
  // get value of the AMI packet header "ActionID"
  hdr  = amiheader_value(pack, ActionID);
  // if amiheader_value does not find header, it will return NULL
  if(hdr != NULL) {
    printf("ActionID: %.*s\n", (int)hdr->len, hdr->buf);
  }

  // clean memory
  amipack_destroy(pack);
  // here we clean only "sp" string
  // string "hdr" is pointing to the memory allocated within AMIPacket
  // and is cleaned with above "amipack_destroy(pack)".
  str_destroy(sp);

  return 0;
}

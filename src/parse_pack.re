/**
 * libamip -- Library with functions for read/create AMI packets
 * Copyright (C) 2016, Stas Kobzar <staskobzar@modulis.ca>
 *
 * This file is part of libamip.
 *
 * libamip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libamip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libamip.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file amip_parse.c
 * @brief AMI (Asterisk Management Interface) packet parser.
 *
 * @author Stas Kobzar <stas.kobzar@modulis.ca>
 */

#include <stdio.h>
#include <string.h>
#include "amip.h"

// introducing types:re2c for prompt packet

enum yycond_pack {
  yyckey,
  yycvalue,
};

int amiparse_pack (const char *pack_str,
                              AMIPacket *pack)
{
  enum pack_type rv = AMI_UNKNOWN;
  enum header_type hdr_type;
  const char *marker = pack_str;
  const char *cur = marker;
  const char *ctxmarker;
  int c = yyckey;
  int len = 0;

  const char *tok = marker;

/*!re2c
  re2c:define:YYCTYPE  = "unsigned char";
  re2c:define:YYCURSOR = "cur";
  re2c:define:YYMARKER = "marker";
  re2c:define:YYCTXMARKER = "ctxmarker";
  re2c:define:YYCONDTYPE = "yycond_pack";
  re2c:define:YYGETCONDITION = "c";
  re2c:define:YYGETCONDITION:naked = 1;
  re2c:define:YYSETCONDITION = "c = @@;";
  re2c:define:YYSETCONDITION:naked = 1;
  re2c:yyfill:enable = 0;

  CRLF = "\r\n";

  ACTION = 'Action';
  EVENT  = 'Event';

  <*> * { return -1; }
  <key,value> CRLF CRLF { goto done; }

  <key> ": " { tok = cur; goto yyc_value; }
  <key> ACTION {
                  len = cur - tok;
                  pack->type = AMI_ACTION;
                  rv = AMI_ACTION;
                  hdr_type = Action;
                  goto yyc_key;
               }
  <key> EVENT  {
                  len = cur - tok;
                  pack->type = AMI_EVENT;
                  rv = AMI_EVENT;
                  hdr_type = Event;
                  goto yyc_key;
               }
  <key> [^: ]+ { len = cur - tok;
                 hdr_type = HDR_UNKNOWN ;
                 goto yyc_key; }

  <value> CRLF / [a-zA-Z] { tok = cur;goto yyc_key; }
  <value> [^\r\n]* {
                      len = cur - tok;
                      char *val = substr(tok, len, 0);
                      amipack_append(pack, hdr_type, "CoreStatus");
                      free (val);
                      goto yyc_value;
                   }

*/

done:
  return rv;
}

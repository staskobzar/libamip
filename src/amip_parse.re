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
#include "amip.h"

// re2c definitions
/*!re2c
  CRLF = "\r\n";
  DIGIT = [0-9];

  ACTION = 'Action';
  DATE   = 'Date';

*/

// introducing types:re2c for prompt packet
enum yycond_prompt {
  yycinit,
  yycminor,
  yycpatch,
  yycmajor,
};

enum yycond_pack {
	yyckey,
	yycvalue,
};

int amiparse_prompt (const char *packet, AMIVer *ver)
{
  // init version structure
  ver->major = 0;
  ver->minor = 0;
  ver->patch = 0;

  const char *cur = packet;
  int c = yycinit;

/*!re2c
  re2c:define:YYCTYPE  = "unsigned char";
  re2c:define:YYCURSOR = "cur";
  re2c:define:YYMARKER = "packet";
  re2c:define:YYCONDTYPE = "yycond_prompt";
  re2c:define:YYGETCONDITION = "c";
  re2c:define:YYGETCONDITION:naked = 1;
  re2c:define:YYSETCONDITION = "c = @@;";
  re2c:define:YYSETCONDITION:naked = 1;
  re2c:yyfill:enable = 0;

  <init,major,minor,patch> * { return RV_FAIL; }
  <init> "Asterisk Call Manager/" :=> major

  <minor,patch> CRLF { goto done; }

  <major> DIGIT { ver->major = ver->major * 10 + (yych - '0'); goto yyc_major; }
  <major> "."   { goto yyc_minor; }

  <minor> DIGIT { ver->minor = ver->minor * 10 + (yych - '0'); goto yyc_minor; }
  <minor> "."   { goto yyc_patch; }

  <patch> DIGIT { ver->patch = ver->patch * 10 + (yych - '0'); goto yyc_patch; }
*/

done:
  return RV_SUCCESS;
}

enum pack_type amiparse_pack (const char *pack_str,
                              AMIPacket *pack)
{
  enum pack_type rv = AMI_UNKNOWN;
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

  <key,value> * { printf("FAILED.\n"); return 1; }
  <key,value> CRLF CRLF { printf("Packet parsed.\n"); goto done; }

  <key> ": " { tok = cur;goto yyc_value; }
  <key> ACTION { len = cur - tok;
                 printf("KEY (fixed): %.*s\n", len, tok);
                 goto yyc_key; }
  <key> DATE   { len = cur - tok;
                 printf("KEY (fixed): %.*s\n", len, tok);
                 goto yyc_key; }
  <key> [^: ]+ { len = cur - tok;
                 printf("KEY (flex): %.*s\n", len, tok);
                 goto yyc_key; }

  <value> CRLF / [a-zA-Z] { tok = cur;goto yyc_key; }
  <value> [^\r\n]* { len = cur - tok;
                     printf("VAL: %.*s\n", len, tok);
                     goto yyc_value;}

*/

done:
  return rv;
}

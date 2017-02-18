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
 * @brief test if packet is AMI (Asterisk Management Interface) complete packet.
 *
 * @author Stas Kobzar <stas.kobzar@modulis.ca>
 */

#include "amip.h"

int amiparse_stanza (const char *packet)
{
  const char *cur = packet;

/*!re2c
  re2c:define:YYCTYPE  = "unsigned char";
  re2c:define:YYCURSOR = "cur";
  re2c:define:YYMARKER = "packet";
  re2c:yyfill:enable = 0;

  CRLF = "\r\n";

  * { return RV_FAIL; }
  .* CRLF CRLF { return RV_SUCCESS; }
*/

}

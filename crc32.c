/* Remote target communications for serial-line targets in custom GDB protocol
                                                                                             
   Copyright 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996,
   1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004
   Free Software Foundation, Inc.
                                                                                             
   This file is part of GDB.
                                                                                             
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
                                                                                             
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
                                                                                             
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* CRC32 algorithm from GDB: gdb/remote.c (GPL!!) */

/* Table used by the crc32 function to calcuate the checksum. */

#include <stdint.h>

static uint32_t crc32_table[256] =
{0, 0};

/* Initialize the CRC table and the decoding table. */
static void
crc32_init(uint32_t *crc32_table)
{
int i, j;
uint32_t c;

	for (i = 0; i < 256; i++) {
		for (c = i << 24, j = 8; j > 0; --j)
			c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : (c << 1);
		crc32_table[i] = c;
	}
}

static uint32_t
crc32 (unsigned char *buf, int len, uint32_t crc)
{
 while (len--)
    {
      crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ *buf) & 255];
      buf++;
    }
  return crc;
}

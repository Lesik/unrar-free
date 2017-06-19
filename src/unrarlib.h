/* Copyright (C) 2004  Jeroen Dekkers <jeroen@dekkers.cx>
   Copyright (C) 2000-2002 by Christian Scheurer (www.ChristianScheurer.ch)
   Copyright (C) 2000-2002 by Johannes Winkelmann (jw@tks6.net)

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#ifndef __URARLIB_H
#define __URARLIB_H

#ifdef __cplusplus
extern "C"
{
#endif

/* Perform cyclical redundancy check (CRC32) - you can disable this
   for a little speed-up */
#define _DO_CRC32_CHECK
  
/* Disable assembly extensions for x86 cpus.  */
#undef  _USE_ASM

/* -- global type definitions --------------------------------------------- */

typedef unsigned char UBYTE;
typedef unsigned short UWORD;
typedef unsigned long UDWORD;

/* This structure is used for listing archive content                       */
struct RAR20_archive_entry	/* These infos about files are  */
{				/* stored in RAR v2.0 archives  */
  char *Name;
  UWORD NameSize;
  UDWORD PackSize;
  UDWORD UnpSize;
  UBYTE HostOS;		/* MSDOS=0,OS2=1,WIN32=2,UNIX=3 */
  UDWORD FileCRC;
  UDWORD FileTime;
  UBYTE UnpVer;
  UBYTE Method;
  UDWORD FileAttr;
};

typedef struct archivelist	/* used to list archives        */
{
  struct RAR20_archive_entry item;
  struct archivelist *next;
} ArchiveList_struct;


/* -- global functions ---------------------------------------------------- */

/* urarlib_get:
 * decompresses and decrypt data from a RAR file to a buffer in system memory.
 *
 *   input: *output         pointer to an empty char*. This pointer will show
 *                          to the extracted data
 *          *size           shows where to write the size of the decompressed
 *                          file
 *                          (**NOTE: URARLib _does_ memory allocation etc.!**)
 *          *filename       pointer to string containing the file to decompress
 *          *rarfile        pointer to a string with the full name and path of
 *                          the RAR file or pointer to a RAR file in memory if
 *                          memory-to-memory decompression is active.
 *          *libpassword    pointer to a string with the password used to
 *                          en-/decrypt the RAR
 *   output: int            returns TRUE on success or FALSE on error
 *                          (FALSE=0, TRUE=1)
 */

extern int urarlib_get (void **output,
			unsigned long *size,
			const char *filename,
			const char *rarfile,
			const char *libpassword);



/* urarlib_list:
 * list the content of a RAR archive.
 *
 *   input: *rarfile        pointer to a string with the full name and path of
 *                          the RAR file or pointer to a RAR file in memory if
 *                          memory-to-memory decompression is active.
 *          *list           pointer to an ArchiveList_struct that can be
 *                          filled with details about the archive
 *                          to the extracted data
 *   output: int            number of files/directories within archive
 */

extern int urarlib_list (const char *rarfile, ArchiveList_struct **list);


/* urarlib_freelist:
 * (after the suggestion and code of Duy Nguyen, Sean O'Blarney
 * and Johannes Winkelmann who independently wrote a patch)
 * free the memory of a ArchiveList_struct created by urarlib_list.
 *
 *    input: *list          pointer to an ArchiveList_struct
 *    output: -
 */

extern void urarlib_freelist (ArchiveList_struct * list);

#ifdef __cplusplus
};
#endif

#endif

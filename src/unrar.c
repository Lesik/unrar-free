/* Copyright (C) 2004  Jeroen Dekkers <jeroen@dekkers.cx>
   Copyright (C) 2004  Ben Asselstine <benasselstine@canada.com>

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <error.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "opts.h"
#include "unrar.h"
#include "unrarlib.h"

/*
 *
 * dos_to_unix_time came from unzip sources.
 * dump_file is based on a simple GPL'd unrar client by Andreas F Borchert.
 * 
 *
 */
extern struct arguments_t arguments;

void
show_copyright ()
{
  printf ("\n");
  printf ("%s %s  Copyright (C) 2004  Ben Asselstine, Jeroen Dekkers\n", 
		  PACKAGE, VERSION);
  printf ("\n");
  return;
}

void
show_list_header (struct unrar_arguments_t *unrar)
{
  printf ("\n");
  printf ("RAR archive %s\n", unrar->archive_filename);
  printf ("\n");
  printf ("Pathname/Comment\n");
  printf
    ("                  Size   Packed Ratio  Date   Time     Attr      CRC   Meth Ver\n");
  printf
    ("-------------------------------------------------------------------------------\n");
  return;
}

void
show_list_footer (struct unrar_arguments_t *unrar)
{
  printf
    ("-------------------------------------------------------------------------------\n");
  return;
}

void
show_list_stats (unsigned int num_files, unsigned int num_compressed_bytes,
		 unsigned int num_bytes)
{
  float ratio;
  ratio = ((float) num_compressed_bytes / (float) num_bytes) * 100;
  printf ("%5u       %10u %8u %3.0f%%\n", num_files, num_bytes,
	  num_compressed_bytes, ratio);
  return;
}

#define DOSTIME_2038_01_18 ((unsigned long)0x74320000L)
#define U_TIME_T_MAX  ((time_t)(unsigned long)0xffffffffL)
#define S_TIME_T_MAX  ((time_t)(unsigned long)0x7fffffffL)
#define YRBASE  1900

time_t
dos_to_unix_time (unsigned long dosdatetime)
{
  time_t m_time;
  struct tm *tm;
  time_t now = time (NULL);

  tm = localtime (&now);
  tm->tm_isdst = -1;		/* let mktime determine if DST is in effect */

  /* dissect date */
  tm->tm_year = ((int) (dosdatetime >> 25) & 0x7f) + (1980 - YRBASE);
  tm->tm_mon = ((int) (dosdatetime >> 21) & 0x0f) - 1;
  tm->tm_mday = ((int) (dosdatetime >> 16) & 0x1f);

  /* dissect time */
  tm->tm_hour = (int) ((unsigned) dosdatetime >> 11) & 0x1f;
  tm->tm_min = (int) ((unsigned) dosdatetime >> 5) & 0x3f;
  tm->tm_sec = (int) ((unsigned) dosdatetime << 1) & 0x3e;

  m_time = mktime (tm);

  if ((dosdatetime >= DOSTIME_2038_01_18) && (m_time < (time_t) 0x70000000L))
    m_time = U_TIME_T_MAX;	/* saturate in case of (unsigned) overflow */
  if (m_time < (time_t) 0L)	/* a converted DOS time cannot be negative */
    m_time = S_TIME_T_MAX;	/*  -> saturate at max signed time_t value */
  return m_time;

}				/* end function dos_to_unix_time() */

void
replace_backslash_with_slash (char *s1)
{
  char *ptr;
  if (!s1)
    return;
  while ((ptr = strchr (s1, '\\')))
    {
      ptr[0] = '/';
      s1 = &ptr[1];
    }
  return;
}

void
unrar_list_item (struct unrar_arguments_t *unrar,
		 ArchiveList_struct * listptr)
{
  char datetime[20];
  char *attr;
  float ratio;

  printf (" %s\n", listptr->item.Name);
  if (listptr->item.UnpSize == 0)
    ratio = 0;
  else
    ratio =
      ((float) listptr->item.PackSize / (float) listptr->item.UnpSize) * 100;
  if (ratio > 100.0)
    ratio = 100.0;
  if (listptr->item.FileTime)
    {
      struct tm filetime;
      time_t unixtime;
      unixtime = dos_to_unix_time ((unsigned long) listptr->item.FileTime);
      localtime_r ((const time_t *) &unixtime, &filetime);
      strftime (datetime, sizeof (datetime), "%d-%m-%y %H:%M", &filetime);
    }
  else
    snprintf (datetime, sizeof (datetime), "00-00-00 00:00");

  if (listptr->item.FileAttr & 0x10)
    attr = ".D....";
  else
    attr = ".....A";

  printf ("            %10u %8u %3.0f%% %s   %s   %08X m%c? %3.1f\n",
	  (unsigned int) listptr->item.UnpSize,
	  (unsigned int) listptr->item.PackSize,
	  ratio,
	  datetime,
	  attr,
	  (unsigned int) listptr->item.FileCRC,
	  listptr->item.Method, (float) (listptr->item.UnpVer / 10.0));
  return;
}

int
unrar_list (struct unrar_arguments_t *unrar, int num_files, char **files)
{
  ArchiveList_struct list;
  ArchiveList_struct *listptr;
  int i, j, n;
  unsigned int count_files = 0;
  unsigned int count_bytes = 0;
  unsigned int count_compressed_bytes = 0;
  list.next = NULL;
  
  n = urarlib_list (unrar->archive_filename,
		    &list.next);
  if (n < 0)
    return n;
  if (unrar->verbose)
    printf ("showing %d files...\n", n);
  if (unrar->verbose)
    printf ("given a list of %d files.\n", num_files);
  listptr = list.next;
  show_list_header (unrar);
  for (i = 0; i < n; i++, listptr = listptr->next)
    {
      replace_backslash_with_slash (listptr->item.Name);
      if (num_files)
	{
	  int found = 0;
	  for (j = 0; j < num_files; j++)
	    {
	      if (unrar->verbose)
		printf ("comparing '%s' vs '%s'\n", files[j],
			listptr->item.Name);
	      if (strcmp (files[j], listptr->item.Name) == 0)
		{
		  found = 1;
		  break;
		}

	    }
	  if (!found)
	    continue;
	}
      count_files++;
      count_compressed_bytes += listptr->item.PackSize;
      count_bytes += listptr->item.UnpSize;
      unrar_list_item (unrar, listptr);
      if (listptr == NULL)	//sanity check.
	break;
    }

  urarlib_freelist (list.next);
  show_list_footer (unrar);
  show_list_stats (count_files, count_compressed_bytes, count_bytes);

  return 0;
}

int
unrar_mkpath (char *path) 
{
  char *path_tmp;
  int i,ret=0;
  if (path == NULL || path[0] == '\0') return (-1);
  path_tmp = strdup(path);
  if (path_tmp == NULL) return (-1);
  for (i=0; path_tmp[i] != '\0'; i++) {
    if (path_tmp[i]=='/') {
      path_tmp[i] = '\0';
      if (path_tmp[0] != '\0') {
        ret = mkdir(path_tmp,0777);
      }
      path_tmp[i] = '/';
    }
  }
  free(path_tmp);
  return ret;
}

int
dump_file (struct unrar_arguments_t *unrar, char *filename, void *data,
	   unsigned long data_size)
{
  int fd;
  int written;
  ssize_t nbytes = 0;
  int fcntl_flags = O_WRONLY | O_CREAT;
  if (unrar->force)
    fcntl_flags |= O_TRUNC;
  else
    fcntl_flags |= O_EXCL;
  fd = open (filename, fcntl_flags, 0666);
  if (fd < 0 && errno == ENOENT) {
    unrar_mkpath (filename);
    fd = open (filename, fcntl_flags, 0666);
  }
  if (fd < 0)
    return -1;

  while (nbytes < data_size)
    {
      written = write (fd, data + nbytes, data_size - nbytes);
      if (written < 0)
	return -1;
      nbytes += written;
    }
  if (close (fd) < 0)
    return -1;
  return 0;
}

void
show_status_line (char *action, char *file, char *status)
{
  printf ("%-11s %-57s %-10s\n", action, file, status);
  return;
}

int
unrar_extract_directory (struct unrar_arguments_t *unrar, char *dir)
{
  char *destination = NULL;
  int ret=0;
  if (unrar->junk_paths)
    return 0;
  if (asprintf (&destination, "%s/%s/", unrar->destination_dir, dir) == -1)
    {
      error (0, 0, "asprintf failed: %m\n");
      return -1;
    }
  if (mkdir (destination, 0777) < 0)
    {
      switch (errno)
	{
	  case EEXIST:
	    if (unrar->force)
	      chmod (destination, 0777);
            break;
          case ENOENT:
            ret = unrar_mkpath(destination);
            if (ret==(-1))
              {
                error(0, 0, "mkpath failed '%s': %m\n", destination);
              }
            break;
          default:
            error (0, 0, "mkdir failed '%s': %m\n", destination);
            ret=(-1);
            break;
	}
    }
  free (destination);
  return ret;
}

int
unrar_extract_file (struct unrar_arguments_t *unrar, char *filename,
		    char *archive_member, time_t FileTime)
{
  int retval;
  char *destination = NULL;
  void *data = NULL;
  unsigned long data_size;
  if (!urarlib_get
      (&data, &data_size, archive_member, unrar->archive_filename,
       unrar->password))
    return -1;
  else
    {
      char *file;
      if (unrar->junk_paths)
	{
	  file = strrchr (filename, '/');
	  if (!file)
	    file = filename;
	}
      else
	file = filename;

      if (asprintf (&destination, "%s/%s", unrar->destination_dir, file) ==
	  -1)
	{
	  error (0, 0, "asprintf failed: %m\n");
	  return 0;
	}
      //where do i put it?  in destination.
      if (unrar->extract_newer)
	{
	  struct stat statbuf;
	  time_t unixtime;
	  int non_existent_files_are_not_newer = 1;
	  retval = lstat (destination, &statbuf);
	  if (retval < 0)
	    {
	      if (non_existent_files_are_not_newer)
		{
		  free (destination);
		  return 1;
		}
	    }
	  else
	    {
	      unixtime = dos_to_unix_time ((unsigned long) FileTime);
	      if (unixtime <= statbuf.st_mtime);
	      {
		free (destination);
		return 1;
	      }
	    }
	}
      //okay put it in destination.
      if (dump_file (unrar, destination, data, data_size) < 0)
	{
	  free (data);
	  free (destination);
	  return -1;
	}
      free (data);
      free (destination);
    }
  return 0;
}

int
unrar_extract (struct unrar_arguments_t *unrar, int num_files, char **files)
{
  ArchiveList_struct list;
  ArchiveList_struct *listptr;
  int i, j, n;
  int retval;
  char *action;
  char *status;
  char *orig_name;
  int num_failed = 0;

  printf ("\n");
  printf ("Extracting from %s\n", unrar->archive_filename);
  printf ("\n");

  list.next = NULL;
  n = urarlib_list (unrar->archive_filename, &list.next);
  if (n < 0)
    return n;

  if (unrar->verbose)
    {
      printf ("showing %d files...\n", n);
      printf ("given a list of %d files.\n", num_files);
    }

  listptr = list.next;
  for (i = 0; i < n; i++, listptr = listptr->next)
    {
      orig_name = strdup (listptr->item.Name);

      replace_backslash_with_slash (listptr->item.Name);
      if (num_files)
	{
	  int found = 0;
	  for (j = 0; j < num_files; j++)
	    {
	      if (unrar->verbose)
		printf ("comparing '%s' vs '%s'\n", files[j],
			listptr->item.Name);
	      if (strcmp (files[j], listptr->item.Name) == 0)
		{
		  found = 1;
		  break;
		}

	    }
	  if (!found)
	    {
	      free (orig_name);
	      if (listptr->item.FileAttr & 0x10)
		continue;
	      action = "Skipping";
	      status = "";
	      show_status_line (action, listptr->item.Name, status);
	      continue;
	    }
	}

      status = "OK";
      if (listptr->item.FileAttr & 0x10)	//is directory.
	{
	  action = "Creating";
	  if ((retval =
	       unrar_extract_directory (unrar, listptr->item.Name)) < 0)
	    {
	      status = "Failed";
	    }
	  else if (retval == 0)
	    {
	      free (orig_name);
	      continue;
	    }

	}
      else			//is file.
	{
	  action = "Extracting";
	  if ((retval =
	       unrar_extract_file (unrar, listptr->item.Name, orig_name,
				   listptr->item.FileTime)) < 0)
	    {
	      status = "Failed";
	    }
	  else if (retval == 1)
	    {
	      action = "Skipping";
	      status = "";
	      show_status_line (action, listptr->item.Name, status);
	      free (orig_name);
	      continue;
	    }
	  else if (retval == 0)
	    {
	      status = "OK";
              show_status_line (action, listptr->item.Name, status);
	      free (orig_name);
	      continue;
	    }
	}
      free (orig_name);
      show_status_line (action, listptr->item.Name, status);
      if (strcmp (status, "Failed") == 0)
	num_failed++;
      if (listptr == NULL)	//sanity check.
	break;
    }

  urarlib_freelist (list.next);
  if (num_failed) {
    printf ("%d Failed\n", num_failed);
    return -1;
  }
  else
    printf ("All OK\n");
  return 0;
}

int
main (int argc, char **argv)
{
  int retval = 0;
  char **files = NULL;
  int num_files = 0;
  
  if (compat_parse_opts (argc, argv, &arguments) == 0) {
    /* compatible mode success */
  } 
  else if (parse_opts (argc, argv, &arguments) < 0)
    exit (1);

  if (arguments.unrar.verbose)
    {
      printf ("archive name is '%s'\n", arguments.unrar.archive_filename);
      printf ("destination directory is '%s'\n",
	      arguments.unrar.destination_dir);
      printf ("mode = %d\n", arguments.unrar.mode);
      printf ("force = %d\n", arguments.unrar.force);
      printf ("extract_newer = %d\n", arguments.unrar.extract_newer);
      printf ("junk_paths = %d\n", arguments.unrar.junk_paths);
    }

  if (arguments.arraylen > 1)
    {
      files = &arguments.args[1];
      num_files = arguments.arraylen - 1;
    }

  show_copyright ();
  if (arguments.unrar.mode == MODE_LIST)
    retval = unrar_list (&arguments.unrar, num_files, files);
  else if (arguments.unrar.mode == MODE_EXTRACT)
    retval = unrar_extract (&arguments.unrar, num_files, files);

  if (retval < 0)
    exit (1);

  exit (0);
}

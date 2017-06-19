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

#ifndef FUNRAR_OPTS_H
#define FUNRAR_OPTS_H 1

enum stow_options_enum_t
{
  OPT_NONE,
  OPT_EXTRACT_NEWER,
  OPT_JUNK_PATHS,
  OPT_FORCE = 'f',
  OPT_PASSWORD = 'p',
  CMD_LIST = 't',
  OPT_VERBOSE = 'v',
  CMD_EXTRACT = 'x',
};
enum unrar_mode_enum_t
{
  MODE_UNKNOWN,
  MODE_EXTRACT,
  MODE_LIST,
};
struct unrar_arguments_t
{
  int mode;			//stow_mode_enum_t
  int force;
  int junk_paths;
  int extract_newer;
  char *destination_dir;
  char *archive_filename;
  int verbose;
  char *password;
};

struct arguments_t
{
  char **args;
  int arraylen;			//for argument processing
  struct unrar_arguments_t unrar;
};
int parse_opts (int argc, char **argv, struct arguments_t *arguments);
int compat_parse_opts (int argc, char **argv, struct arguments_t *arguments);

#endif

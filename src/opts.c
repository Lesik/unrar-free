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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <argp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "opts.h"

#define FULL_VERSION PACKAGE_NAME " " PACKAGE_VERSION
const char *argp_program_version = FULL_VERSION;
const char *argp_program_bug_address = "<" PACKAGE_BUGREPORT ">";
static char doc[] = "Extract files from rar archives.";
static char args_doc[] = "ARCHIVE [FILE...] [DESTINATION]";
struct arguments_t arguments;

static struct argp_option options[] = {
  {"extract", CMD_EXTRACT, 0, 0, "Extract files from archive (default)", 0},
  {"list", CMD_LIST, 0, 0, "List files in archive", 1},
  {"force", OPT_FORCE, 0, 0, "Overwrite files when extracting", 2},
  {"extract-newer", OPT_EXTRACT_NEWER, 0, 0,
   "Only extract newer files from the archive", 3},
  {"extract-no-paths", OPT_JUNK_PATHS, 0, 0,
   "Don't create directories while extracting", 3},
  {"password", OPT_PASSWORD, 0, 0, "Decrypt archive using a password", 3},
  {"verbose", OPT_VERBOSE, 0, OPTION_HIDDEN, "Verbosely list files extracted", 3},
  {0}
};


void
free_arguments ()
{
  if (arguments.args)
    free (arguments.args);
  if (arguments.unrar.destination_dir)
    free (arguments.unrar.destination_dir);
  if (arguments.unrar.archive_filename)
    free (arguments.unrar.archive_filename);
  if (arguments.unrar.password)
    free (arguments.unrar.password);
  return;
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the INPUT argument from `argp_parse', which we
     know is a pointer to our arguments structure. */

  struct arguments_t *arguments = state->input;
  char *pass;

  switch (key)
    {
    case CMD_EXTRACT:
      arguments->unrar.mode = MODE_EXTRACT;
      break;
    case CMD_LIST:
      arguments->unrar.mode = MODE_LIST;
      break;
    case OPT_FORCE:
      arguments->unrar.force = 1;
      break;
    case OPT_JUNK_PATHS:
      arguments->unrar.junk_paths = 1;
      break;
    case OPT_EXTRACT_NEWER:
      arguments->unrar.extract_newer = 1;
      break;
    case OPT_PASSWORD:
      if (arguments->unrar.password == NULL)
      {
	      if ((pass = getpass ("Password:")))
		arguments->unrar.password = strdup (pass);
      }
      break;
    case OPT_VERBOSE:
      arguments->unrar.verbose = 1;
      break;
    case ARGP_KEY_INIT:
      free_arguments ();
      arguments->args = NULL;
      arguments->arraylen = 0;
      break;
    case ARGP_KEY_ARG:
      arguments->arraylen++;
      arguments->args =
	(char **) realloc (arguments->args,
			   arguments->arraylen * sizeof (char *));
      arguments->args[state->arg_num] = arg;
      break;
    case ARGP_KEY_END:
      if (arguments->arraylen > 0)
	{
	  char *file;
	  struct stat statbuf;
	  file = realpath (arguments->args[0], NULL);
	  if (lstat (file, &statbuf) == -1)
	    {
	      free (file);
	      error (0, 0, "invalid archive '%s': %m", arguments->args[0]);
	      argp_usage (state);
	    }
	  else
	    {
	      if (!(S_ISDIR (statbuf.st_mode)))
		arguments->unrar.archive_filename = file;
	      else
		{
		  free (file);
		  error (0, 0, "invalid archive '%s': is a directory",
			 arguments->args[0]);
		  argp_usage (state);
		}
	    }
	}

      if (arguments->arraylen > 1)
	{
	  char *dir;
	  struct stat statbuf;
	  dir = realpath (arguments->args[arguments->arraylen - 1], NULL);
	  if (lstat (dir, &statbuf) == -1)
	    free (dir);
	  else
	    {
	      if (S_ISDIR (statbuf.st_mode))
		{
		  arguments->unrar.destination_dir = dir;
		  arguments->args[arguments->arraylen - 1] = NULL;
		  arguments->arraylen--;
		}
	      else
		free (dir);
	    }
	}
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

int
set_default_arguments (struct unrar_arguments_t *unrar)
{
  if (unrar->mode == MODE_UNKNOWN)
    unrar->mode = MODE_EXTRACT;
  if (unrar->destination_dir == NULL)
    unrar->destination_dir = realpath ("./", NULL);
  return 0;
}

struct argp argp = { options, parse_opt, args_doc, doc };

int
parse_opts (int argc, char **argv, struct arguments_t *arguments)
{
  int retval;
  setenv ("ARGP_HELP_FMT", "no-dup-args-note", 1);
  atexit (free_arguments);
  retval = argp_parse (&argp, argc, argv, 0, 0, arguments);
  if (retval < 0)
    argp_help (&argp, stdout, ARGP_HELP_EXIT_ERR | ARGP_HELP_SEE,
	       PACKAGE_NAME);
  set_default_arguments (&arguments->unrar);

  if (arguments->arraylen == 0)
    {
      error (0, 0, "Archive not specified\n");
      argp_help (&argp, stdout, ARGP_HELP_EXIT_ERR | ARGP_HELP_SEE,
		 PACKAGE_NAME);
      return -1;
    }

  return 0;
}


/**
 * @brief Decide a valid unrar command.
 * To decide a string is an unrar command or not
 * @param a the string
 * @retval true it is an unrar command
 * @retval false it is not an unrar command
 */
int compat_iscmd(char *a) {
  if (strcmp(a,"e")==0
   || strcmp(a,"l")==0
   || strcmp(a,"lt")==0
   || strcmp(a,"lb")==0
   || strcmp(a,"p")==0
   || strcmp(a,"t")==0
   || strcmp(a,"v")==0
   || strcmp(a,"vt")==0
   || strcmp(a,"vb")==0
   || strcmp(a,"x")==0
  ) {
    return (1==1);
  }
  return (1==0);
}

/**
 * @brief To execute an unrar command.
 * Set arguments to execute an unrar command
 * @param a the command
 * @param the arguments structure
 */
void compat_execcmd(char *a, struct arguments_t *arguments) {
  if (strcmp(a,"e")==0) {
    arguments->unrar.mode = MODE_EXTRACT;
    arguments->unrar.junk_paths = 1;
  } else if (strcmp(a,"l")==0) {
    arguments->unrar.mode = MODE_LIST;
  } else if (strcmp(a,"lt")==0) {
    arguments->unrar.mode = MODE_LIST;
  } else if (strcmp(a,"lb")==0) {
    arguments->unrar.mode = MODE_LIST;
  } else if (strcmp(a,"p")==0) {
  } else if (strcmp(a,"t")==0) {
    arguments->unrar.mode = MODE_LIST;
  } else if (strcmp(a,"v")==0) {
    arguments->unrar.mode = MODE_LIST;
    arguments->unrar.verbose = 1;
  } else if (strcmp(a,"vt")==0) {
    arguments->unrar.mode = MODE_LIST;
    arguments->unrar.verbose = 1;
  } else if (strcmp(a,"vb")==0) {
    arguments->unrar.mode = MODE_LIST;
    arguments->unrar.verbose = 1;
  } else if (strcmp(a,"x")==0) {
    arguments->unrar.mode = MODE_EXTRACT;
  } else {
    return;
  }
}

/**
 * @brief Execute an unrar switch.
 * Set arguments to execute an unrar switch
 * @param a the string
 * @param arguments the arguments strcture
 * @retval 0 it is a switch (start with "-") and arguments is changed
 * @retval 1 it is not a switch and arguments is unchanged
 * @retval 2 it is a stop switch "--" and arguments is unchanged
 */
int compat_execswitch(char *a, struct arguments_t *arguments) {
  char *swtch,*opt,*pass;
  if (a[0]=='-') {
    swtch=&(a[1]);
  } else {
    /* not a switch */
    return 1;
  }
  
  if (strcmp(swtch,"-")==0) {
    /* stop switch */
    return 2;
  } else if (strcmp(swtch,"ep")==0) {
    arguments->unrar.junk_paths = 1;
  } else if (strcmp(swtch,"o+")==0) {
    arguments->unrar.force = 1;
  } else if (strcmp(swtch,"o-")==0) {
    arguments->unrar.force = 0;
  } else if (strncmp(swtch,"p",1)==0) {
    opt = &(swtch[1]);
    if (strcmp(opt,"-")==0) {
      /* don't ask for password */
    } else if (opt[0] != '\0') {
      /* copy password from cmd line */
      pass = opt;
      arguments->unrar.password = strdup(pass);
    } else {
      /* ask password */
      if ((pass = getpass ("Password:")) != NULL) {
        arguments->unrar.password = strdup(pass);
      }
    }
  } else if (strcmp(swtch,"u")==0) {
    arguments->unrar.extract_newer = 1;
  } else {
  }
  return 0;
}

/**
 * @brief Add an string to arguments.args.
 * Add a string to an arguments structure
 * @param a the string
 * @param arguments the arguments strcture
 */
void compat_addargs(char *a, struct arguments_t *arguments) {
  int arg_num;
  arg_num = arguments->arraylen;
  arguments->arraylen++;
  arguments->args =
    (char **) realloc (arguments->args,
                       arguments->arraylen * sizeof (char *));
    arguments->args[arg_num] = a;
}

int
compat_parse_opts(int argc, char **argv, struct arguments_t *arguments1) {
  int retval=0,i;
  /* iscmd? */
  if (argc <=2 || !compat_iscmd(argv[1])) {
    return -1;
  }
  /* init */
  free_arguments();
  arguments1->args=NULL;
  arguments1->arraylen=0;
  /* cmd */
  compat_execcmd(argv[1],arguments1);
  /* switch */
  for (i=2 ; i<argc ; i++) {
    retval = compat_execswitch(argv[i],arguments1);
    if (retval == 1) {
      break;
    } else if (retval == 2) {
      i++;
      break;
    }
  }
  /* args */
  for ( ; i<argc ; i++) {
    compat_addargs(argv[i],arguments1);
  }
  /* end */
  retval=0;
  if (arguments1->arraylen > 0) {
    char *file;
    struct stat statbuf;
    file = realpath (arguments1->args[0], NULL);
    if (lstat (file, &statbuf) == -1) {
      free (file);
      /* error (0, 0, "invalid archive '%s': %m", arguments1->args[0]); */
      retval=-1;
    } else {
      if (!(S_ISDIR (statbuf.st_mode))) {
        arguments1->unrar.archive_filename = file;
      } else {
        free (file);
        /*error (0, 0, "invalid archive '%s': is a directory",
               arguments1->args[0]);*/
        retval=-1;
      }
    }
  }
  if (retval<0) {
    free_arguments();
    memset(&arguments,0,sizeof(arguments));
    return -1;
  }
  if (arguments1->arraylen > 1) {
    char *dir;
    struct stat statbuf;
    dir = realpath (arguments1->args[arguments1->arraylen - 1], NULL);
    if (lstat (dir, &statbuf) == -1)
      free(dir);
    else {
      if (S_ISDIR (statbuf.st_mode)) {
        arguments1->unrar.destination_dir = dir;
        arguments1->args[arguments1->arraylen - 1] = NULL;
        arguments1->arraylen--;
      } else 
        free (dir);
    }
  }
  
  set_default_arguments (&arguments1->unrar);

  if (arguments1->arraylen == 0)
  {
    /*error (0, 0, "Archive not specified\n");*/
    free_arguments();
    memset(&arguments,0,sizeof(arguments));
    return -1;
  }
  /* argument parsing success, register free_arguments to atexit */
  atexit (free_arguments);
  return 0;
}

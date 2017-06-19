/* 
   Copyright (C) 2004  Jeroen Dekkers <jeroen@dekkers.cx>
   Copyright (C) 2000-2002  Christian Scheurer (www.ChristianScheurer.ch)
   Copyright (C) 2000-2002  Johannes Winkelmann (jw@tks6.net)
   RAR decompression code:
   Copyright (c) 1993-2002  Eugene Roshal

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

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <ftw.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "unrarlib.h"
/*
#include "unrar29.h"
#include "unrar20.h"
#include "unrar15.h"
*/

int UnpackXX_fileoutput(FILE *outputfile,int rarmethod,FILE *inputfile,int DestUnpSize, int UnpPackedSize, int Flags) {
  int filepos,intfd;
  int retval=0;
/*  static unpack_data_t *unpack_data=NULL;

  filepos = ftell(inputfile);

  if (outputfile==NULL) {
    #ifdef _DEBUG_LOG
    fprintf(stderr,"Fatal! Cannot open output file!\n");
    #endif
    return (1==0);
  }
  
  if (unpack_data==NULL) {
    unpack_data = malloc(sizeof(unpack_data_t));
    ppm_constructor(&unpack_data->ppm_data);
  }
  unpack_data->rarvm_data.mem = NULL;
  unpack_data->old_filter_lengths = NULL;
  unpack_data->PrgStack.array = NULL;
  unpack_data->Filters.array = NULL;
  unpack_data->PrgStack.num_items = 0;
  unpack_data->Filters.num_items = 0;
  unpack_data->unp_crc = 0xffffffff;
  unpack_data->dest_unp_size = DestUnpSize;
  unpack_data->pack_size = UnpPackedSize;
  unpack_data->ofd = fileno(outputfile);
  intfd = fileno(inputfile);
  lseek(intfd,filepos,SEEK_SET);
  switch(rarmethod) {
  case 29:
    retval = rar_unpack29(intfd,Flags&LHD_SOLID, unpack_data);
    break;
  case 15:
    retval = rar_unpack15(intfd,Flags&LHD_SOLID, unpack_data);
    break;
  case 20:
  case 26:
    retval = rar_unpack20(intfd,Flags&LHD_SOLID, unpack_data);
    break;
  }

  fseek(inputfile,filepos+UnpPackedSize,SEEK_SET);
  fflush(outputfile);*/
  return retval;
}

int Unpack29_fileoutput(FILE *outputfile,FILE *inputfile,int DestUnpSize, int UnpPackedSize, int Flags) {
  return UnpackXX_fileoutput(outputfile,29,inputfile,DestUnpSize,UnpPackedSize,Flags);
}

void Unpack29(FILE *inputfile,int DestUnpSize, int UnpPackedSize, int Flags) {
  FILE *ofile;
  static int i=0;
  int c;
  char tmpfilename[100];
  extern unsigned char *temp_output_buffer;
  extern unsigned long *temp_output_buffer_offset;

  snprintf(tmpfilename,sizeof(tmpfilename)-1,"/tmp/unrar_tmpf_%06d",i);
  i++;
  #ifdef UNPACK29_KEEP_TEMP_FILE
  ofile = fopen(tmpfilename,"w+b");
  #else
  ofile = tmpfile();
  #endif
  
  
  if (ofile==NULL) {
    #ifdef _DEBUG_LOG
    fprintf(stderr,"Fatal! Cannot open tmp file!\n");
    #endif
    return;
  }
  
  Unpack29_fileoutput(ofile,inputfile,DestUnpSize,UnpPackedSize,Flags);
  if (temp_output_buffer != NULL) {
    fseek(ofile,0,SEEK_SET);
    while (!feof(ofile)) {
      if ((*temp_output_buffer_offset) > DestUnpSize) {
        #ifdef _DEBUG_LOG
        fprintf(stderr,"Fatal! Buffer overrun during compression!\n");
        #endif
        break;
      }
      c = fgetc(ofile);
      if (c==EOF) {
        break;
      }
      temp_output_buffer[(*temp_output_buffer_offset)] = c;
      (*temp_output_buffer_offset)++;
    }
  }
  fclose(ofile);
}

static int removeDir_nftw_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  int ret = remove(fpath);
  return ret;
}

static int removeDir(char *path) {
  return nftw(path, removeDir_nftw_cb, 3, FTW_DEPTH | FTW_PHYS);
}

void Unpack29unar(FILE *inputfile,int DestUnpSize, int UnpPackedSize, const char *arcName, const char *argNameO) {
  extern char **environ;

  extern unsigned char *temp_output_buffer;
  extern unsigned long *temp_output_buffer_offset;

  static char unar[] = {"unar"};

  char *argName = NULL;

  const char * unarARGV[10];
  pid_t unarPID;
  posix_spawn_file_actions_t unarFileAction;

  char tempdirTemplate[] = {"/tmp/unrarfreeunarXXXXXX"};
  char *tempdir = NULL;

  FILE *dataFile = NULL;
  char *dataFileName = NULL;
  int dataFileNameLen = 0;
  char *oldCwd = NULL;

  int filepos;
  int i;

  filepos = ftell(inputfile);

  /* replace \ to / in argName */
  argName = strdup(argNameO);
  if (argName == NULL) {
    goto Unpack29unarEnd;
  }
  for (i=0; argName[i] != '\0'; i++) {
    if (argName[i] == '\\') {
      argName[i] = '/';
    }
  }

  /* create temp directory */
  tempdir = mkdtemp(tempdirTemplate);
  if (tempdir == NULL) {
    goto Unpack29unarEnd;
  }

  /* spawn unar to extract the file */
  oldCwd = getcwd(NULL, 0);
  if (chdir(tempdir) != 0) {
    goto Unpack29unarEnd;
  }
  memset(unarARGV, 0, sizeof(unarARGV));
  unarARGV[0] = unar;
  unarARGV[1] = "-q";
  unarARGV[2] = "-f";
  unarARGV[3] = "-D";
  unarARGV[4] = "-o";
  unarARGV[5] = ".";
  unarARGV[6] = arcName;
  unarARGV[7] = argName;
  posix_spawn_file_actions_init(&unarFileAction);
  posix_spawn_file_actions_addclose(&unarFileAction, 0);
  posix_spawn_file_actions_addclose(&unarFileAction, 1);
  posix_spawn_file_actions_addclose(&unarFileAction, 2);
  if (posix_spawnp(&unarPID, unar, &unarFileAction, NULL, unarARGV, environ)!=0) {
    goto Unpack29unarEnd;
  }
  waitpid(unarPID, NULL, 0);
  chdir(oldCwd);

  dataFileNameLen = strlen(tempdir)+strlen(argName)+1;
  dataFileName = (char *)malloc(sizeof(char)*(dataFileNameLen+1));
  snprintf(dataFileName, dataFileNameLen+1, "%s/%s", tempdir, argName);
  dataFile = fopen(dataFileName, "r");
  if (dataFileName != NULL) {
    free(dataFileName);
    dataFileName = NULL;
  }
  if (dataFile == NULL) {
    goto Unpack29unarEnd;
  }

  if (temp_output_buffer != NULL) {
    while (!feof(dataFile)) {
      int c;
      if ((*temp_output_buffer_offset) > DestUnpSize) {
        #ifdef _DEBUG_LOG
        fprintf(stderr,"Fatal! Buffer overrun during compression!\n");
        #endif
        break;
      }
      c = fgetc(dataFile);
      if (c==EOF) {
        break;
      }
      temp_output_buffer[(*temp_output_buffer_offset)] = c;
      (*temp_output_buffer_offset)++;
    }
  }

 Unpack29unarEnd:
  if (dataFile != NULL) {
    fclose(dataFile);
    dataFile = NULL;
  }
  if (argName != NULL) {
    free(argName);
    argName = NULL;
  }
  if (oldCwd != NULL) {
    free(oldCwd);
    oldCwd = NULL;
  }
  fseek(inputfile,filepos+UnpPackedSize,SEEK_SET);
  if (tempdir != NULL) {
    removeDir(tempdir);
    tempdir = NULL;
  }
  return;
}

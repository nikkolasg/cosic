/*
 * =====================================================================================
 *
 *       Filename:  utils.c
 *
 *    Description:  implementation of some utility functions
 *
 *        Version:  1.0
 *        Created:  11/25/2016 03:31:23 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (), nikkolasg@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/random.h>
#include <sys/syscall.h>

#include "utils.h"


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  random_bytes
 *  Description:  calls getrandom syscall on linux filling *buf* with *len* bytes. It 
 *                returns false if error or if returned number is not equal to *len*.
 *                XXX TODO make that platform independant...
 * =====================================================================================
 */
bool random_bytes(void *buf, size_t len)
{
   int n;
   n = syscall(SYS_getrandom,buf,len,0);
   if (n == -1) {
       return false;
   } else if (n < len) {
       return false;
   }
   return true;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  read_file
 *  Description:  reads *len* bytes from the file *filename* into *buffer*. If
 *  the file's length is less than *len*, it returns false. If the file is not a
 *  regular file (i.e. a pipe etc), it returns false. Otherwise it returns true.
 * =====================================================================================
 */
bool read_file(const char *filename, void * buffer, size_t len)
{
    int fd;
    size_t file_len;
    struct stat file_info;

    if ((fd = open (filename, O_RDONLY)) == -1) {
        perr("could not open private key file %s",filename);
        return false;
    }

    fstat (fd, &file_info);
    if (!S_ISREG (file_info.st_mode)) {
        // XXX Could catch return value and print 
        close(fd);
        perr("private key %s is not a file",filename);
        return false;
    }

    file_len = file_info.st_size;
    if (file_len < len) {
        close(fd);
        perr("private key %s contains less than %zu bytes",filename,len);
        return false;
    }

    if (read(fd,buffer,len) != len) {
        close(fd);
        perr("not able to read %zu bytes from private key file",len);
        return false;
    }
    close(fd);
    return true;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  print_hexa
 *  Description:  Prints *prepend*, then *len* bytes pointed by the given *buffer* in
 *  hexadecimal format, followed by "\n".
 * =====================================================================================
 */
void print_hexa(const char *prepend,const void *buffer, size_t len)
{
    const uint8_t *buff = buffer;
    printf("%s",prepend);
    for(size_t i=0; i < len; i++) {
        printf("%02hhx",buff[i]);
    }
    printf("\n");
}

bool util_malloc(void **ptr,size_t len) {
    assert(ptr != NULL); 
    
    *ptr = malloc(len);
    if (*ptr == NULL) {
        return false;
    }
    return true;
}

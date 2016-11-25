/*
 * =====================================================================================
 *
 *       Filename:  utils.h
 *
 *    Description:  some utilies / macros used all over the code.
 *
 *        Version:  1.0
 *        Created:  11/25/2016 02:44:02 PM
 *       Revision:  none
 *       Compiler:  clang
 *
 *         Author:  nikkolasg (), nikkolasg@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#pragma once

#include <stdbool.h>

/*
 * Utility macro definitions
 */
#define pout(fmt,args...) printf("[+] " fmt "\n",args)

#define perr(fmt,args...) fprintf(stderr,"[-] " fmt "\n",args)

#define fail exit(EXIT_FAILURE)

#define pfail(fmt,args...) perr(fmt,args); fail

/*
 * Utility functions
 */
bool read_file(const char *filename,void * buffer,size_t length);
void print_hexa(const char *prepend, const void *buffer, size_t len);

/*
 * =====================================================================================
 *
 *       Filename:  net.c
 *
 *    Description:  network operations related primitives
 *
 *        Version:  1.0
 *        Created:  11/25/2016 02:32:19 PM
 *       Revision:  none
 *       Compiler:  clang
 *
 *         Author:  nikkolasg (), nikkolasg@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <arpa/inet.h>
#include <stdbool.h>

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  net_ip_valid
 *  Description:  Check if the given string represents a valid ipv4 address.
 * =====================================================================================
 */
bool net_is_ip_valid(char * ip)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}		



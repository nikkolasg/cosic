/*
 * =====================================================================================
 *
 *       Filename:  net.h
 *
 *    Description:  header for the network primitive operations
 *
 *        Version:  1.0
 *        Created:  11/25/2016 02:38:46 PM
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
#include <event2/listener.h>
#include "cosi.h"

typedef struct {
    char *remote;
    cosi_proto *proto;
    // our own secret material
    material *material;
    // did we already received the server identity of the remote party
    bool si_received;
    // TODO later, make a full dispatcher which handles different type of
    // message...

} conn_state;

void run(const int, void *data);
void conn_state_init(conn_state *s, struct sockaddr *add,int len,void *gdata);
void conn_state_process_si(conn_state *s,const uint8_t id[UUID_SIZE],
                           const uint8_t *buffer, size_t len);
void conn_state_free(conn_state *s);
bool net_is_ip_valid(char * ip);

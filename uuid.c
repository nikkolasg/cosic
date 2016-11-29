/*
 * =====================================================================================
 *
 *       Filename:  uuid.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/28/2016 10:09:26 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (), nikkolasg@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include "uuid.h"
#include "utils.h"

const uint8_t cosi_packet_id[UUID_SIZE] = 
                {133,69,219,199,46,184,90,196,162,150,191,174,40,230,90,65};
const uint8_t server_identity_id[UUID_SIZE] = 
                {123,158,19,108,196,136,89,99,160,180,130,1,179,26,25,117};

bool uuid_equal(uint8_t u[UUID_SIZE], uint8_t v[UUID_SIZE]) {
    if (u == NULL || v == NULL ) {
        pfail("uuid equal: null pointer");
    }
    return memcmp(u,v,UUID_SIZE);
}


/*
 * =====================================================================================
 *
 *       Filename:  uuid.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/27/2016 10:59:08 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (), nikkolasg@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */
#pragma once

#include <stdbool.h>
#include <string.h>

#include "utils.h"

#define UUID_SIZE 16

const uint8_t cosi_packet_id[UUID_SIZE];


bool uuid_equal(uint8_t u[UUID_SIZE], uint8_t v[UUID_SIZE]);

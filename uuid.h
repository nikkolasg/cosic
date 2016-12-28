#pragma once

#include <stdbool.h>
#include <string.h>

#include "utils.h"

#define UUID_SIZE 16

const uint8_t cosi_packet_id[UUID_SIZE];
const uint8_t server_identity_id[UUID_SIZE];


bool uuid_equal(uint8_t u[UUID_SIZE], uint8_t v[UUID_SIZE]);

#pragma once
#include <stdbool.h>
// XXX Change that into a generic "send" function so no need to include
// bufferevent in here...
#include <event2/bufferevent.h>

#include "utils.h"
#include "uuid.h"
#include "ed25519.h"
#include "cosi.pb-c.h"

typedef struct {
    const uint8_t * secret;
    uint8_t * random;
    uint8_t * commit;
    uint8_t * challenge;
    uint8_t * response;
    const char * remote;
} cosi_state;

typedef struct {
    const char * remote;
    cosi_state * state;
    const material * material;
} cosi_proto;

void cosi_state_init(cosi_state *state,const char *remote,const uint8_t *secret);
bool cosi_state_commit(cosi_state * state);
bool cosi_state_challenge(cosi_state *state,const uint8_t *challenge);
bool cosi_state_response(cosi_state *state);
inline bool cosi_state_check(cosi_state * state);

void cosi_proto_init(cosi_proto *proto,const char *remote,const material *material);
void cosi_proto_process(cosi_proto *proto,struct bufferevent *bev,uint8_t id[UUID_SIZE],uint8_t *buffer,size_t len);
void cosi_proto_announcement(cosi_proto *proto,struct bufferevent *bev,ProtocolPacket *packet);
void cosi_proto_challenge(cosi_proto *proto, struct bufferevent *bev,ProtocolPacket *packet);
bool cosi_proto_send_packet(struct bufferevent *bev,ProtocolPacket *packet);
void cosi_packet_exchange_endpoints(ProtocolPacket *packet);

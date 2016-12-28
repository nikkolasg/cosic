#pragma once
#include <stdbool.h>
// XXX Change that into a generic "send" function so no need to include
// bufferevent in here...
#include <event2/bufferevent.h>

#include "net.h"
#include "utils.h"
#include "uuid.h"
#include "ed25519.h"
#include "cosi.pb-c.h"

/*
 * cosi_proto is the layer between the network and the cosi_state. It handles
 * the protobuf part, sending to the network and the exceptions.
 */
typedef struct cosi_proto cosi_proto;
/*  
 * cosi_state holds the cryptographic parts in order to sucessfully generate a
 * collective signature. It only handles the crypto part and *not* the protobuf
 * / network part (handled by cosi_proto).
 */
typedef struct cosi_state cosi_state;

/*
 * cosi_platform implements the net_platform interface. It receives all cosi
 * messages, creates cosi_protos and dispatch to cosi_proto.
 */
typedef struct {
    /*  the net_platform implementation */
    net_platform *platform;
    /* the cryptographic material read at init */
    const material *m; 
    /* currently running cosi protocol 
     * NOTE: This PoC only handles one protocol at a time. Later, if needed,
     * accomodate with multiple running at the same time. It should be
     * relatively easy with the separation between the platform and the protocol. */
    cosi_proto *proto;
} cosi_platform;

/*
 * cosi_proto is the layer between the network and the cosi_state. It handles
 * the protobuf part, sending to the network and the exceptions.
 */
struct cosi_proto{
    cosi_state * state;
};

/*  
 * cosi_state holds the cryptographic parts in order to sucessfully generate a
 * collective signature. It only handles the crypto part and *not* the protobuf
 * / network part (handled by cosi_proto).
 */
struct cosi_state {
    const material *m;
    uint8_t * random;
    uint8_t * commit;
    uint8_t * challenge;
    uint8_t * response;
    const char * remote;
};



net_platform * cosi_platform_new(const material *);
void cosi_platform_free(cosi_platform *);

cosi_proto * cosi_proto_new(const material *material);
void cosi_proto_free(cosi_proto *p);
void cosi_proto_process(cosi_proto *proto,const net_conn * c,const ProtocolPacket *packet);

cosi_state *  cosi_state_new(const material *m);
void cosi_state_free();
/*
 *  cosi_state_commit generates the random/commit key pair used during the
 *  signing.
 */
bool cosi_state_commit(cosi_state * state);
/*
 * cosi_state_challenge stores the challenge given in argument. NOTE: this steps
 * is un-necessary for this PoC state, but if cosic were to support an
 * intermediate node's role in the tree, this method is already there.
 */
bool cosi_state_challenge(cosi_state *state,const uint8_t *challenge);
/*
 * cosi_state_reponse generate the response out of the informations contained in
 * the cosi_state. Access with state->reponse.
 */
bool cosi_state_response(cosi_state *state);

bool cosi_proto_announcement(cosi_proto *proto,const ProtocolPacket *incoming,ProtocolPacket *outgoing);
bool cosi_proto_challenge(cosi_proto *proto, const ProtocolPacket *incoming,ProtocolPacket *outgoing);

void cosi_packet_exchange_endpoints(const ProtocolPacket *incoming,ProtocolPacket *outgoing);

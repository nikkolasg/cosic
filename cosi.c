#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cosi.h"
#include "cosi.pb-c.h"
#include "utils.h"
#include "uuid.h"
#include "ed25519.h"

#include <openssl/sha.h>
#include <event2/buffer.h>

const uint32_t cosi_phase_ann   = 1;
const uint32_t cosi_phase_comm  = 2;
const uint32_t cosi_phase_chall = 3;
const uint32_t cosi_phase_resp  = 4;


void cosi_platform_process(net_platform *plat, const net_conn *c,const net_packet *packet);
bool cosi_platform_accept_id(net_platform *plat, const uint8_t id[UUID_SIZE]);

/*
 * Returns a new platform
 */
net_platform * cosi_platform_new(const material *m) {
    cosi_platform *cp;
    net_platform *np;
    cosi_proto *proto;
    if ((cp = malloc(sizeof(cosi_platform))) == NULL){
        pfail("could not allocate a cosi_platform"); 
    }
    if ((np = malloc(sizeof(net_platform))) == NULL) {
        pfail("could not allocate a net_platform for cosi");
    }

    proto = cosi_proto_new(m);
    np->process = cosi_platform_process;
    np->accept = cosi_platform_accept_id;
    *cp = (cosi_platform) {np,m,proto};
    return (net_platform*)cp;  
}

/*
 * De-allocate the cosi_platform
 */
void cosi_platform_free(cosi_platform *p) {
    assert(p && p->platform && p->proto);
    free(p->platform);
    cosi_proto_free(p->proto);
    free(p);
}

/*
 * check if the id is a cosi packet id or not
 */
bool cosi_platform_accept_id(net_platform *plat, const uint8_t id[UUID_SIZE]) {
    if (memcmp(id,cosi_packet_id,UUID_SIZE) != 0) {
        return false;
    }
    return true;
}

void cosi_platform_process(net_platform *plat, const net_conn *c,const net_packet *packet) {
    assert(plat && c && c->si && packet);     

    cosi_platform *p = (cosi_platform*) plat;
    ProtocolPacket *incoming;


    //print_hexa(" => ",buffer,len);
    if ((incoming = protocol_packet__unpack(NULL,packet->len,packet->buffer)) == NULL) {
        perr("%s: cosi proto could not unpack protocol packet out of %zu bytes",c->si->address,packet->len);
        return;
    }

    assert(p->proto);
    cosi_proto_process(p->proto,c,incoming);
    protocol_packet__free_unpacked(incoming,NULL);
}



/*  
 *  Returns a freshly allocated cosi_state struct
 */
cosi_proto* cosi_proto_new(const material *material) {
    cosi_proto *proto;
    cosi_state *state;
    if ((proto = malloc(sizeof(cosi_proto))) == NULL) {
        pfail("could not allocate a cosi_proto");
    }
    state = cosi_state_new(material);
    proto->state = state;
    return proto;
}

/*  
 *  De-allocate the cosi_state struct (coming from cosi_state_new) 
 */
void cosi_proto_free(cosi_proto * p) {
    assert(p && p->state);
    cosi_state_free(p->state);
    free(p);
}

/*
 * cosi_proto_process takes the packet and process it further to the inner
 * cosi_state and reply to the sender accordingly.
 */
void cosi_proto_process(cosi_proto *proto,const net_conn * c,const ProtocolPacket *incoming) {
    assert(proto && c && incoming);

    size_t pack_len;
    size_t whole_len;
    size_t written;
    uint8_t *buffer;
    bool ret=true;


    ProtocolPacket outgoing = PROTOCOL_PACKET__INIT; 
    outgoing.info = incoming->info;
    cosi_packet_exchange_endpoints(incoming,&outgoing);

    switch (incoming->phase) {
        case cosi_phase_ann:
            ret = cosi_proto_announcement(proto,incoming,&outgoing);
            break;
        case cosi_phase_chall:
            ret = cosi_proto_challenge(proto,incoming,&outgoing);
            break;
        // theses cases should not happen in this simplistic cosi version yet
        // since we are a leaf node.
        //case cosi_phase_comm:
        //    cosi_proto_commitment(proto,bev,packet);
        //case cosi_phase_resp:
        //    cosi_proto_response(proto,bev,packet);
    }

    if (!ret) {
        return;
    }

    pack_len = protocol_packet__get_packed_size(&outgoing);
    whole_len = htonl(pack_len + UUID_SIZE);

    if((buffer = malloc(pack_len)) == NULL) {
        perr("%s: could not malloc outgoing cosi packet",c->si->address);
        return;
    }
    
    written = protocol_packet__pack(&outgoing,buffer);
    net_packet packet;
    packet.id = (uint8_t *)cosi_packet_id;
    packet.buffer = buffer;
    packet.len = pack_len;
    c->send(c,&packet);
}

/*
 * cosi_proto_announcement process the announcement message. It returns true if
 * the outgoing packet is ready to be sent back or false if an error occured.
 */
bool cosi_proto_announcement(cosi_proto *proto,const ProtocolPacket *incoming,ProtocolPacket *outgoing) {
    assert(proto && proto->state);
    // not an assert since this is external information
    if(incoming->ann == NULL) {
        perr("cosi proto announcement given null announcement"); 
        return false;
    }

    pout("cosi proto announcement received");

    cosi_state *state = proto->state;

    // generate commitment
    if (!cosi_state_commit(state)) {
        return false;
    }
    
    Commitment protoCommit = COMMITMENT__INIT;
    ProtobufCBinaryData protobufComm = {ED25519_POINT_SIZE,state->commit};
    protoCommit.comm = protobufComm;
    outgoing->comm = &protoCommit;
    outgoing->phase = cosi_phase_comm;
    return true;
}

/*
 * cosi_proto_challenge process the challenge message. It returns true if
 * the outgoing packet is ready to be sent back or false if an error occured.
 */
bool cosi_proto_challenge(cosi_proto *proto, const ProtocolPacket *incoming,ProtocolPacket *outgoing) {
    assert(incoming->chal != NULL);
    assert(proto->state != NULL);

    cosi_state *state = proto->state;
    uint8_t *challenge = incoming->chal->chall.data;

    if(!cosi_state_challenge(state,challenge)) {
        return true;
    }

    if(!cosi_state_response(state)) {
        return true;
    }

    Response response = RESPONSE__INIT;
    ProtobufCBinaryData protobufResponse = {ED25519_SCALAR_SIZE,state->response};
    response.resp = protobufResponse;
    outgoing->resp = &response;
    outgoing->phase = cosi_phase_resp;
    return true;
}

/*
 * Set the outgoing's TO/FROM endpoints in the OverlayInformation to the FROM/TO
 * of the incoming's endpoints.
 */
void cosi_packet_exchange_endpoints(const ProtocolPacket *incoming,ProtocolPacket *outgoing) {
    if (!incoming->info || !incoming->info->tree_node_info) {
        pfail("protocol packet has no overlay message ??");
    }
    
    TreeNodeInfo *tni = incoming->info->tree_node_info;
    Token *tmp = tni->to;
    tni->to = tni->from;
    tni->from = tmp;
    outgoing->info->tree_node_info = tni;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  cosi_state_init
 *  Description:  init the cosi struct with the secret key and the remote node
 *  address. IT DOES NOT MAKE A COPY OF THE SECRET, only takes the address.
 *  Let's avoid create copies of secret everywhere.
 *  NOTE: you MUST call cosi_state_free when finished in order to free
 *  the random bytes.
 * =====================================================================================
 */
cosi_state * cosi_state_new(const material *m) {
    assert(m);
    cosi_state *s;
    if ((s = malloc(sizeof(cosi_state))) == NULL) {
        pfail("could not allocate for cosi_state");
    }

    s->m = m;
    return s;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  cosi_state_commit
 *  Description:  generate the random / commit pair.
 *                state->random & state->commit are guaranteed to be non NULL if
 *                the call returned true.
 * =====================================================================================
 */
bool cosi_state_commit(cosi_state *state) {
    assert(state);
    
    uint8_t *random;

    // allocate random
    if ((random = (uint8_t*) malloc(ED25519_SCALAR_SIZE)) == NULL) {
        perr("%s cosi: could not allocate for random",state->remote);
        return false;
    } else if (!random_bytes(random,ED25519_SCALAR_SIZE)) {
        perr("%s cosi: could not get random bytes",state->remote);
        return false;
    }


    // compute commit = random * G
    if ((state->commit = (uint8_t*) malloc(ED25519_POINT_SIZE)) == NULL) {
        perr("%s cosi: state commit can't malloc the bytes",state->remote);
        return false;
    }
    memset(state->commit,0,ED25519_POINT_SIZE);

    state->random = random;

    unsigned char * urandom = state->random;
    unsigned char * ucommit = state->commit;

    ge_p3 R;

    sc_reduce(urandom);
    ge_scalarmult_base(&R, urandom);
    ge_p3_tobytes(ucommit, &R);

    print_hexa("cosi: generated commit",state->commit,ED25519_POINT_SIZE);
    return true;
}
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  cosi_state_commit
 *  Description:  Store a copy of the given challenge inside the state.
 *                state->challenge is guaranteed to be non NULL if the call
 *                returned true.
 * =====================================================================================
 */
bool cosi_state_challenge(cosi_state *state,const uint8_t *challenge) {
    assert(state);

    if ((state->challenge = (uint8_t*) malloc(ED25519_SCALAR_SIZE)) == NULL) {
        perr("%s cosi: state challenge can't malloc the bytes",state->remote);
        return false;
    }
    memcpy(state->challenge,challenge,ED25519_SCALAR_SIZE);
    print_hexa("cosi: stored challenge ",state->challenge,ED25519_SCALAR_SIZE);
    return true;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  cosi_state_response
 *  Description:  Generate the response to send.
 *                state->response is guaranteed to be non NULL if the call
 *                returned true.
 * =====================================================================================
 */
bool cosi_state_response(cosi_state *state) {
    assert(state && state->m && state->challenge && state->random);
    
    if ((state->response = (uint8_t*) malloc(ED25519_SCALAR_SIZE)) == NULL) {
        perr("%s cosi: state response can't malloc the bytes",state->remote);
        return false;
    }
    memset(state->response,0,ED25519_SCALAR_SIZE);
    
    // r = challenge * secret + random
    sc_muladd(state->response, state->m->sk, state->challenge, state->random);
    print_hexa("cosi: generated response ", state->response, ED25519_SCALAR_SIZE);
    return true;
} 

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  cosi_state_free
 *  Description:  free the state structure,ie. free the challenge,random,
 *  response and commit fields
 * =====================================================================================
 */
void cosi_state_free(cosi_state *state) {
    assert(state == NULL);

    free(state->challenge);
    free(state->commit);
    free(state->random);
    free(state->response);

    state->challenge = NULL;
    state->commit = NULL;
    state->random = NULL;
    state->response = NULL;
}

extern inline bool cosi_state_check(cosi_state * state){ 
    if (state == NULL 
            || state->m == NULL 
            || state->remote == NULL) {
        return false;
    }
    return true;
}

// CoSi signature: s = commit + challenge * private
// where challenge = H( COMMIT || Public || Message)
// Difference with EdDSA: challenge = H( R(priv) || Public || Message)
// where R(priv) is deterministic according to the seed of the private key.
// buff MUST BE of size 64 bytes == ED25519_SIG_SIZE
// output is sig = challenge || s
void cosi_state_sig(cosi_state *state,uint8_t *msg,size_t msg_len,void *buff) {
    assert(state->m != NULL);
    assert(state->response != NULL);
    assert(state->commit != NULL);

    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx,state->commit,ED25519_POINT_SIZE);
    SHA512_Update(&ctx,state->m->pk,ED25519_PUBLIC_SIZE);
    SHA512_Update(&ctx,msg,msg_len);
    SHA512_Final(state->challenge,&ctx);

    sc_reduce(state->challenge);
    sc_muladd(buff+32,state->m->sk,state->challenge,state->random);
    
    memcpy(buff,state->commit,ED25519_POINT_SIZE);
}

bool cosi_verify_signature(uint8_t *sig,uint8_t *public,uint8_t *message,size_t len) {
    uint8_t *rb = sig;
    uint8_t *sb = sig + 32;
    uint8_t rcheck[ED25519_POINT_SIZE];
    uint8_t k[SHA512_DIGEST_LENGTH];

    ge_p3 A;
    ge_p2 R;

    if (ge_frombytes_negate_vartime(&A, public) != 0) {
        return -1;
    }

    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx,rb,ED25519_POINT_SIZE);
    SHA512_Update(&ctx,public,ED25519_PUBLIC_SIZE);
    SHA512_Update(&ctx,message,len);
    SHA512_Final(k,&ctx);

    sc_reduce(k);

    ge_double_scalarmult_vartime(&R, k, &A, sb);
    ge_tobytes(rcheck, &R);

    // no need to get paranoid with constant time equality since this is to
    // check public values...
    // https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time
    return memcmp(rcheck,rb,ED25519_POINT_SIZE) == 0;
}

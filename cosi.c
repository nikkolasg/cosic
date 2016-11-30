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


void cosi_proto_init(cosi_proto * proto,const char *remote,const material *material) {
    if(!proto) {
        pfail("cosi proto init given null pointer",NULL);
    }

    cosi_state *state;
    if (!util_malloc((void*)&state,sizeof(cosi_state))) {
        pfail("%s: can not allocate cosi_state",remote);
    }
    cosi_state_init(state,remote,material);

    proto->state = state;
    proto->remote = remote;
    proto->material = material;
}

void cosi_proto_process(cosi_proto *proto,struct bufferevent *bev,uint8_t id[UUID_SIZE],uint8_t *buffer,size_t len) {
    afail(proto->remote == NULL,"cosi proto null proto remote");

    // check if the id is a cosi packet
    if (memcmp(id,cosi_packet_id,UUID_SIZE) != 0) {
        perr("%s: cosi proto process: non cosi packet id received",proto->remote);
        return;
    }

    // unmarshal packet
    ProtocolPacket *packet;
    //print_hexa(" => ",buffer,len);
    if ((packet = protocol_packet__unpack(NULL,len,buffer)) == NULL) {
        perr("%s: cosi proto could not unpack protocol packet out of %zu bytes",proto->remote,len);
        return;
    }

    switch (packet->phase) {
        case cosi_phase_ann:
            cosi_proto_announcement(proto,bev,packet);
            break;
        case cosi_phase_chall:
            cosi_proto_challenge(proto,bev,packet);
            break;
        // theses cases should not happen in this simplistic cosi version yet
        // since we are a leaf node.
        //case cosi_phase_comm:
        //    cosi_proto_commitment(proto,bev,packet);
        //case cosi_phase_resp:
        //    cosi_proto_response(proto,bev,packet);
    }
    protocol_packet__free_unpacked(packet,NULL);
}

void cosi_proto_announcement(cosi_proto *proto,struct bufferevent *bev,ProtocolPacket *p) {
    if(p->ann == NULL) {
        perr("%s: cosi proto announcement given null announcement",proto->remote);                  
        return;
    }
    assert(proto->state != NULL);
    pout("%s: cosi proto announcement received",proto->remote);

    cosi_state *state = proto->state;
    // generate commitment
    if (!cosi_state_commit(state)) {
        return;
    }
    ProtocolPacket packet = PROTOCOL_PACKET__INIT;
    packet.info = p->info;
    Commitment protoCommit = COMMITMENT__INIT;
    ProtobufCBinaryData protobufComm = {ED25519_POINT_SIZE,state->commit};
    protoCommit.comm = protobufComm;
    packet.comm = &protoCommit;
    packet.phase = (uint32_t) 2;

    if (!cosi_proto_send_packet(bev,&packet)) {
        perr("%s: cosi proto announcement could not send back commitment",proto->remote);
    } else {
        pout("%s: cosi proto sent back commitment",proto->remote);
    }
}

void cosi_proto_challenge(cosi_proto *proto, struct bufferevent *bev,ProtocolPacket *packet) {
    assert(packet->chal != NULL);
    assert(proto->state != NULL);

    cosi_state *state = proto->state;
    uint8_t *challenge = packet->chal->chall.data;

    if(!cosi_state_challenge(state,challenge)) {
        return;
    }

    if(!cosi_state_response(state)) {
        return;
    }

    ProtocolPacket p = PROTOCOL_PACKET__INIT; 
    p.info = packet->info;
    Response response = RESPONSE__INIT;
    ProtobufCBinaryData protobufResponse = {ED25519_SCALAR_SIZE,state->response};
    response.resp = protobufResponse;
    p.resp = &response;
    p.phase = cosi_phase_resp;
   
    if (!cosi_proto_send_packet(bev,&p)) {
        pout("%s: cosi proto challenge error sending packet",proto->remote);
    } else {
        pout("%s: cosi proto challenge sent back response",proto->remote);
    }
}

// XXX Refactor: put that in net + use GOTO
bool cosi_proto_send_packet(struct bufferevent *bev,ProtocolPacket *packet) {
    size_t pack_len = protocol_packet__get_packed_size(packet);
    size_t whole_len = htonl(pack_len + UUID_SIZE);
    size_t written;
    uint8_t *buffer;
    bool ret=true;
    cosi_packet_exchange_endpoints(packet);

    if((buffer = malloc(pack_len)) == NULL) {
        return false;
    }

    written = protocol_packet__pack(packet,buffer);

    // unmarshal packet
    ProtocolPacket *unbuffer;
    //print_hexa(" => ",buffer,len);
    if (( unbuffer = protocol_packet__unpack(NULL,pack_len,buffer)) == NULL) {
        perr("cosi_proto_send_packet: could not unpack packet packed");
        return false;
    }
    
    /*pout("send pack len : %zu",pack_len);*/
    /*print_hexa("send pack : ",buffer,pack_len);*/
    // first write the size then id then packet
    if (bufferevent_write(bev,(void *)(&whole_len),4) == -1) {
        ret = false;
    }

    if (bufferevent_write(bev,(void *)&cosi_packet_id,UUID_SIZE) == -1) {
        ret = false;
    }

    if (bufferevent_write(bev,(void *)buffer,pack_len) == -1) {
        ret = false;
    }
    pout("sent %zu bytes to evbuff",(unsigned long) ntohl(whole_len));

    free(buffer);
    return ret;
}

void cosi_packet_exchange_endpoints(ProtocolPacket *packet) {
    if (!packet->info || !packet->info->tree_node_info) {
        pfail("protocol packet has no overlay message ??");
    }
    
    TreeNodeInfo *tni = packet->info->tree_node_info;
    Token *tmp = tni->to;
    tni->to = tni->from;
    tni->from = tmp;
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
void cosi_state_init(cosi_state *state,const char *remote,const material *m) {
    assert(state != NULL);

    state->m = m;
    state->remote = remote;

    pout("new cosi initiated with %s",remote);
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
    if (!cosi_state_check(state)) {
        return false;
    }
    
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
    if (!cosi_state_check(state)) {
        return false;
    }
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
    if (!cosi_state_check(state)) {
        return false;
    }
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

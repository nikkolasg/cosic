#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cosi.h"
#include "utils.h"
#include "ed25519.h"

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  cosi_state_init
 *  Description:  init the cosi struct with the secret key and the remote node
 *  address. IT DOES NOT MAKE A COPY OF THE SECRET, only takes the address.
 *  Let's avoid create copies of secret everywhere.
 *                state->secret & state->remote are guaranteed to be non NULL if
 *                the call returned true.
 *  NOTE: you MUST call cosi_state_free when finished in order to free
 *  the random bytes.
 * =====================================================================================
 */
bool cosi_state_init(cosi_state *state,char *remote,uint8_t *secret) {
    if (state == NULL) {
        return false;
    }

    state->secret = secret;
    state->remote = remote;

    pout("New cosi initiated with %s",remote);
    return true;
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

    state->random = random;

    unsigned char * urandom = state->random;
    unsigned char * ucommit = state->commit;

    ge_p3 R;

    sc_reduce(urandom);
    ge_scalarmult_base(&R, urandom);
    ge_p3_tobytes(ucommit, &R);

    pout("%s cosi: generated commit",state->remote);
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
bool cosi_state_challenge(cosi_state *state,uint8_t *challenge) {
    if (!cosi_state_check(state)) {
        return false;
    }
    if ((state->challenge = (uint8_t*) malloc(ED25519_SCALAR_SIZE)) == NULL) {
        perr("%s cosi: state challenge can't malloc the bytes",state->remote);
        return false;
    }

    memcpy(state->challenge,challenge,ED25519_SCALAR_SIZE);
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

    // r = challenge * secret + random
    sc_muladd(state->response, state->secret,state->challenge, state->random);
    sc_reduce(state->response);
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
    if (state == NULL) {
        perr("cosi state free-ing NULL pointer",NULL);
        return;
    }

    free(state->challenge);
    free(state->commit);
    free(state->random);
    free(state->response);

    state->challenge = NULL;
    state->commit = NULL;
    state->random = NULL;
    state->response = NULL;
}

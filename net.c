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
#include <stdbool.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "uuid.h"
#include "utils.h"
#include "net.h"

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


// Connection has something to read for us
static void read_cb(struct bufferevent *bev, void *ctx)
{
    // first read the size which is in a uint32_t then type of message
    // which is unfortunatly currently a UUID => 16bytes
    uint32_t size = 0;
    uint8_t id[UUID_SIZE] = {0};
    uint8_t *packet;
    size_t n = 0;
    size_t ssize = sizeof(size);


    conn_state *state = (conn_state *) ctx;
    // lets check that we have the whole packet
    struct evbuffer *input = bufferevent_get_input(bev);
    if ((n = evbuffer_copyout(input, (void *) (&size), ssize)) == -1) {
        perr("%s: evbuffer_copyout not working",state->remote);
        return;
    } else if (n < ssize) {
        perr("%s: evbuffer not have enough data to read size",state->remote);
        return;
    }
    size = ntohl(size);
    if ((n = evbuffer_get_length(input)) < size+4) {
        perr("%s: evbuffer not have enough data to read whole packet %zu/%lu",
                state->remote,n,(unsigned long)size);
        return;
    }

    pout("%s: evbuffer.length() %zu vs read size %lu",state->remote,
            evbuffer_get_length(input),(unsigned long) size);

    // Now actually read the thing 
    // XXX TODO refactor here so we re-use code.

    // read the size
    if ((n = bufferevent_read(bev,(void *) (&size),ssize)) != ssize) {
        perr("%s: read only %zu/%zu for size of packet",state->remote,n,ssize);
        return;
    }
    size = ntohl(size);
    // read the type
    n = bufferevent_read(bev,(void *) id,UUID_SIZE);
    if (n != UUID_SIZE) {
        perr("%s: read only %zu/%d for type of packet",state->remote,n,UUID_SIZE);
        return;
    }

    // packet size
    size = size - UUID_SIZE; 
    if ((packet = malloc(size)) == NULL) {
        perr("%s: could not allocate packet buffer",state->remote);
        return;
    }

    pout("%s: will call bufferevent_read with size %lu",state->remote,(unsigned long) size);
    if((n = bufferevent_read(bev,(void *) packet,size)) != size) {
        // XXX TODO check how to "wait" for next bytes if there are not enough
        perr("%s: read only %zu/%lu from connection for filling packet",
                state->remote,n,(unsigned long)size);
        return;
    }    

    afail(state->proto == NULL,"%s: conn state proto is null.",state->remote);

    // XXX TODO later make a full dispatcher depending on type with function
    // pointers.
    if (!state->si_received) {
        conn_state_process_si(state,id,packet,size); 
    } else {
        cosi_proto_process(state->proto,bev,id,packet,size);
        free(packet);
    }
}

// Event callback from connection - same for every connection for now.
static void generic_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_ERROR)
            perr("Error from bufferevent",NULL);
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
            bufferevent_free(bev);
    }
    conn_state_free((conn_state *)ctx);
}

// Accept connection callback from listener
static void accept_conn_cb(struct evconnlistener *listener,
                           evutil_socket_t fd, // fd of the new conn
                           struct sockaddr *address,  // remote address
                           int socklen, // len of address
                           void *ctx) // generic data from run()
{
    struct event_base *base = evconnlistener_get_base(listener);
    int flags = BEV_OPT_CLOSE_ON_FREE;
    struct bufferevent *bev = bufferevent_socket_new(base, fd, flags);

    // read + write at least 4 bytes of size + 16 bytes of type
    bufferevent_setwatermark(bev,EV_READ | EV_WRITE,4+16,0);
    conn_state *cstate;
    if((cstate = malloc(sizeof(cstate))) == NULL) {
        perr("could not malloc state");
        return;
    }
    conn_state_init(cstate,address,socklen,ctx);

    // register read + event cbs
    bufferevent_setcb(bev, read_cb, NULL, generic_event_cb, (void*)cstate);

    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

// Event callback from listener 
static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    perr("Got an error %d (%s) on the listener.Shutting down.", 
            err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

// libevent log method override.
static void libevent_log(int severity, const char *msg)
{
    const char *s;
    switch (severity) {
        case _EVENT_LOG_DEBUG: s = "debug"; break;
        case _EVENT_LOG_MSG:   s = "msg";   break;
        case _EVENT_LOG_WARN:  s = "warn";  break;
        case _EVENT_LOG_ERR:   s = "error"; break;
        default:               s = "?";     break; /* never reached */
    }
    perr("[%s] %s", s, msg);
}

void conn_state_init(conn_state *s, struct sockaddr *add,int len,void *gdata) {
    if (!s) {
        pfail("conn state init received null state",NULL);
    }

    struct sockaddr_in *sin= (struct sockaddr_in*) add;
    char *remote;
   
    // translate address into readable output
    if (!(remote = malloc(INET_ADDRSTRLEN))) {
        pfail("conn state init could not allocate remote address",NULL);
    }
    inet_ntop(AF_INET, &(sin->sin_addr), remote, INET_ADDRSTRLEN);

    s->remote = remote;
    s->material = (material *) gdata;
    s->si_received = false;
    util_malloc((void *)&(s->proto),sizeof(cosi_proto));
    // XXX TODO later, have a full dispatcher instead of hard coding the
    // processor
    cosi_proto_init(s->proto,remote,s->material);
}

void conn_state_process_si(conn_state *s,const uint8_t id[UUID_SIZE],
                           const uint8_t *buffer, size_t len) {
    //assert(s != NULL && s->remote != NULL);
    // check if id is server identity
    if(memcmp(id,server_identity_id,UUID_SIZE) != 0) {
        perr("%s: conn state received non server identity type",s->remote);
        return;
    }

    ServerIdentity *si;
    if ((si = server_identity__unpack(NULL,len,buffer)) == NULL) {
        perr("%s: conn state error unpack server identity",s->remote);
        return;
    }

    s->si_received = true;
    pout("%s: conn state received identity (addr %s)",s->remote,si->address);
}

void conn_state_free(conn_state *s) {
    if (!s) {
        return;
    }
    if (s->remote) {
        free(s->remote);
        s->remote = NULL;
    }

    free(s);
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  run
 *  Description:  starts a listener on *address*. data is a generic pointer that
 *  will be given to every callbacks used by libevent.
 * =====================================================================================
 */
void run (const int port, void *data)
{
    struct event_base * ebase;
    struct evconnlistener *listener;
    struct sockaddr_in sin;
    int ret; 
    int flags,backlog;
    
    pout("running with libevent %s",event_get_version());
    event_set_log_callback(libevent_log);
    if (!(ebase = event_base_new())) { 
        pfail("could not allocate event base",NULL); 
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    // listen on 0.0.0.0
    sin.sin_addr.s_addr = htonl(0);
    sin.sin_port = htons(port);

    flags = LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE;
    // how many incoming connection not yet accepted at same time
    backlog = -1;
    listener = evconnlistener_new_bind(ebase, accept_conn_cb, data,
             flags,backlog, (struct sockaddr*)&sin, sizeof(sin));

    if (!listener) {
        pfail("could not allocate new listener",NULL);
    }
  
    evconnlistener_set_error_cb(listener, accept_error_cb);

    ret = event_base_dispatch(ebase);

    if (ret == -1) {
        pfail("error with dispatching -> abort.",NULL); 
    }
}



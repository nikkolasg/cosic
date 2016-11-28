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
    conn_state *state = (conn_state *) ctx;

    // first read the size which is in a uint32_t then type of message
    // which is unfortunatly currently a UUID => 16bytes
    uint32_t size;
    uint8_t id[UUID_SIZE] = {0};
    uint8_t *packet;
    size_t n = 0;
    size_t ssize = sizeof(size);

    // read the size
    if ((n == bufferevent_read(bev,(void *) (&size),ssize)) != ssize) {
        perr("%s: could not read size of packet",state->remote);
        return;
    }

    // read the type
    n = bufferevent_read(bev,(void *) id,UUID_SIZE);
    if (n != UUID_SIZE) {
        perr("%s: could not read type of packet",state->remote);
        return;
    }

    // packet size
    size = size - UUID_SIZE; 
    if ((packet = malloc(size)) == NULL) {
        perr("%s: could not allocate packet buffer",state->remote);
        return;
    }

    if((n == bufferevent_read(bev,(void *) packet,size)) != size) {
        // XXX TODO check how to "wait" for next bytes if there are not enough
        perr("%s: could not read enough from connection for filling packet",
                state->remote);
        return;
    }    

    afail(state->proto == NULL,"%s: conn state proto is null.",state->remote);

    // XXX TODO later make a full dispatcher depending on type with function
    // pointers.
    cosi_proto_process(state->proto,bev,id,packet,size);
}

// Event callback from connection - same for every connection for now.
static void generic_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_ERROR)
            perr("Error from bufferevent",NULL);
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
            bufferevent_free(bev);
    }
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
    // XXX TODO later, have a full dispatcher instead of hard coding the
    // processor
    cosi_proto_init(s->proto,remote,s->material);
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
             flags,-1, (struct sockaddr*)&sin, sizeof(sin));

    if (!listener) {
        pfail("could not allocate new listener",NULL);
    }
  
    evconnlistener_set_error_cb(listener, accept_error_cb);

    ret = event_base_dispatch(ebase);

    if (ret == -1) {
        pfail("error with dispatching -> abort.",NULL); 
    }
}



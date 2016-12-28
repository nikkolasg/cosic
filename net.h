/*
 * =====================================================================================
 *
 *       Filename:  net.h
 *
 *    Description:  header for the network primitive operations
 *
 *        Version:  1.0
 *        Created:  11/25/2016 02:38:46 PM
 *       Revision:  none
 *       Compiler:  clang
 *
 *         Author:  nikkolasg (), nikkolasg@gmail.com
 *   Organization:  
 *
 * ===================================================================================== */
#pragma once

#include <stdbool.h>
#include <event2/listener.h>

#include "uuid.h"
#include "cosi.pb-c.h"

/*
 * net_packet is a generic container for any kind of packet the network might
 * receive. 
 */
typedef struct {
    /* id of the packet (size UUID_SIZE) */
    uint8_t *id;
    /* buffer from network */
    uint8_t * buffer;
    /* size of the BUFFER */
    size_t len;
} net_packet;

/* 
 * net_conn holds the information about the remote party as well as a method to
 * send a net_packet to this remote party.
 */
typedef struct net_conn net_conn;
/*  
 * send is a abstract method given to net_platform's impl. so they can send back
 * a message if needed 
 * XXX For the moment a simple "response" to the sender is sufficient for this
 * experimental PoC, no need to handle a directory of all addresses / public
 * keys known etc..
 */
typedef void (*send_packet) (const net_conn *c,const net_packet *packet);

/* private part of net_endpoint (see below)  */
typedef struct net_conn_private net_conn_private;

struct net_conn {
    /*  to send a packet to the endpoint */
    send_packet send;
    /* server identity of the remote endpoint */
    ServerIdentity *si;
    /* the private part of a net_endpoint struct */
    net_conn_private *priv;
};


/*  
 * net_platform is an interface used by the network layer to dispatch message to
 * the right recipient. One message can be dispatched to multiple recipients.
 */
typedef struct net_platform net_platform;
/*
 * process is an abstract method that must be implemented by net_platform's
 * implementation. If the implementation->accept() returns true when given the
 * packet's id, this method is called with this packet. 
 */
typedef void (*process) (net_platform *plat, const net_conn* c,const net_packet *packet);
/*
 * accept_id is an abstract method that must be implemented by net_platform's
 * implementation. Given an id, this method must return true if the net_platform
 * wants to process this packet. Multiple net_platform can process the same
 * packet.
 */
typedef bool (*accept_id) (net_platform *plat,const uint8_t id[UUID_SIZE]);

struct net_platform {
    /* the process method receiving messages */
    process process;
    /*  does this platform accept or not a specific id ?  */
    accept_id accept;
};

/*
 * net_platform_list contains a list of all platforms available to dispatch
 * messages. This is created in the main and given the main libevent loop.
 * XXX Sufficient for this PoC, later, having a dynamic list should not be
 * difficult
 */
typedef struct {
    // XXX later transform that into maps
    net_platform *platforms;
} net_platform_list;


/*
 * run starts the main libevent loop. It expects the port as first arguments and
 * a net_platform_list as a second arguments in order to dispatch the messages.
 */
void run(const int,const net_platform_list * );

net_conn * net_conn_new(const net_platform_list *);
void net_conn_free(net_conn *);
void net_conn_process_si(net_conn *c,const net_packet*);
void net_conn_dispatch(net_conn *c,const net_packet*);
bool net_is_ip_valid(char * ip);

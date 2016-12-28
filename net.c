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
 * Private definitions
 */
struct net_conn_private {
    /*  the bufferevent associated with the connection. NOTE: This impl. is not
     *  multithreaded and this bufferevent is likely to change between
     *  receptions of new messages. Thus it is not safe to use in a
     *  multithreaded environment. */
    struct bufferevent *bev;
    /* did we already received the server identity of the remote party  */
    bool si_received;
    /*  the list of platforms that can receive packets */
    const net_platform_list *list;
};


/*
 * Returns true if the ip given is a valid ip address.
 */
bool net_is_ip_valid(char * ip)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}		

/*
 * Method call when a read event occurs on a connection.
 */
static void read_cb(struct bufferevent *bev, void *ctx)
{
    // first read the size which is in a uint32_t then type of message
    // which is unfortunatly currently a UUID => 16bytes
    uint32_t size = 0;
    uint8_t id[UUID_SIZE] = {0};
    uint8_t *buffer;
    size_t n = 0;
    size_t ssize = sizeof(size);
    net_conn *c = (net_conn *) ctx;
    

    assert(c && c->priv && c->si);
    c->priv->bev = bev;
    const char *address = c->si->address;

    // check that the whole packet is readable
    struct evbuffer *input = bufferevent_get_input(bev);
    if ((n = evbuffer_copyout(input, (void *) (&size), ssize)) == -1) {
        perr("%s: evbuffer_copyout not working",address);
        return;
    } else if (n < ssize) {
        perr("%s: evbuffer not have enough data to read size",address);
        return;
    }
    size = ntohl(size);
    if ((n = evbuffer_get_length(input)) < size+4) {
        perr("%s: evbuffer not have enough data to read whole packet %zu/%lu",
                address,n,(unsigned long)size);
        return;
    }

    pout("%s: evbuffer.length() %zu vs read size %lu",address,
            evbuffer_get_length(input),(unsigned long) size);

    // Now actually read the thing 
    // XXX TODO refactor here so we re-use code.

    // read the size
    if ((n = bufferevent_read(bev,(void *) (&size),ssize)) != ssize) {
        perr("%s: read only %zu/%zu for size of packet",address,n,ssize);
        return;
    }
    size = ntohl(size);
    // read the type
    n = bufferevent_read(bev,(void *) id,UUID_SIZE);
    if (n != UUID_SIZE) {
        perr("%s: read only %zu/%d for type of packet",address,n,UUID_SIZE);
        return;
    }

    // packet size
    size = size - UUID_SIZE; 
    if ((buffer = malloc(size)) == NULL) {
        perr("%s: could not allocate packet buffer",address);
        return;
    }

    pout("%s: will call bufferevent_read with size %lu",address,(unsigned long) size);
    if((n = bufferevent_read(bev,(void *) buffer,size)) != size) {
        // XXX TODO check how to "wait" for next bytes if there are not enough
        perr("%s: read only %zu/%lu from connection for filling packet",
                address,n,(unsigned long)size);
        return;
    }    

    net_packet packet;
    packet.id = id;
    packet.buffer = buffer;
    packet.len = size;
    // XXX TODO later make a full dispatcher depending on type with function
    // pointers.
    if (!c->priv->si_received) {
        net_conn_process_si(c,&packet); 
    } else {
        net_conn_dispatch(c,&packet);
    }
    free(buffer);
}

/*
 * Event error callback from connection - same for every connection for now.
 */ 
static void generic_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_ERROR)
            perr("Error from bufferevent",NULL);
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
            bufferevent_free(bev);
    }
    net_conn_free((net_conn*)ctx);
}

/* 
 * Accept connection callback from listener called when there is a new 
 * incoming connection.
 */
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
    
    net_platform_list *list = (net_platform_list *)ctx;
    net_conn *c = net_conn_new(list);

    // register read + event cbs
    bufferevent_setcb(bev, read_cb, NULL, generic_event_cb, (void*)c);

    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

/*
 * Event callback from listener called when an error occurs wih an incoming 
 * new connection.
 */
static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    perr("Got an error %d (%s) on the listener.Shutting down.", 
            err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

/*
 * libevent log method override.
 */ 
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

/*
 * writes the size, the id and the buffer.
 */
void net_conn_send_packet(const net_conn *c,const net_packet *packet) {
    assert(c && c->priv && c->priv->bev);
    assert(c && c->si && c->si->address);

    struct bufferevent *bev = c->priv->bev;
    /*pout("send pack len : %zu",pack_len);*/
    /*print_hexa("send pack : ",buffer,pack_len);*/
    // first write the size then id then packet
    if (bufferevent_write(bev,(void *)(&(packet->len + UUID_SIZE)),4) == -1) {
        perr("%s: could not write size",c->si->address);
        return;
    }

    if (bufferevent_write(bev,(void *)&(packet->id),UUID_SIZE) == -1) {
        perr("%s: could not write id",c->si->address);
        return;
    }

    if (bufferevent_write(bev,(void *)packet->buffer,packet->len) == -1) {
        perr("%s: could not write buffer",c->si->address);
        return;
    }
    pout("sent %zu bytes to evbuff",(unsigned long) ntohl(packet->len));
}

/*
 * Allocate and returns a freshly now net_conn 
 */
net_conn*  net_conn_new(const net_platform_list *list) {
    net_conn *c;
    if ((c = malloc(sizeof(net_conn))) == NULL) {
        pfail("not able to allocate net_conn");
    }
    
    c->priv->si_received = false;
    c->priv->list = list;
    c->send = net_conn_send_packet;
    return c;
}


/*  
 * Free a previously allocated net_conn
 */
void net_conn_free(net_conn * c) {
    assert(c && c->si);
    server_identity__free_unpacked(c->si,NULL);
    free(c);
}

/*  
 * process the Server Identity from the remote party. It's a special case that
 * happens on the first message of each connection, so no need to go with a full
 * platform.
 */
void net_conn_process_si(net_conn *s,const net_packet *packet) {
    assert(s && s->si);
    assert(packet && packet->id && packet->buffer && packet->len > 0);
    const uint8_t *id = packet->id;
    const uint8_t *buffer = packet->buffer;
    size_t len = packet->len;
    char * address = s->si->address;
    // check if id is server identity
    if(memcmp(id,server_identity_id,UUID_SIZE) != 0) {
        perr("%s: conn received non server identity type",address);
        return;
    }

    ServerIdentity *si;
    if ((si = server_identity__unpack(NULL,len,buffer)) == NULL) {
        perr("%s: conn error unpack server identity",address);
        return;
    }

    s->priv->si_received = true;
    s->si = si;
    pout("%s: conn received identity",address);
}

/* 
 * net_conn_dispatch iterates over all platforms and dispatch the
 * packet to the platforms that accepts the net_packet->id. 
 */
void net_conn_dispatch(net_conn *s, const net_packet *packet) {
    assert(s && s->priv && s->priv->list && packet);  
    net_platform *plat = s->priv->list->platforms;
    // all platforms are already checked in run()
    // XXX Later when multiple platforms are supported
    /*for(int i=0; i < list->procs_len; i++) {*/
        /*if (!list->platforms[i]->accept_id(packet->id)) {*/
            /*continue;*/
        /*}*/
        /*list->platforms[i]->process(s,packet)*/
    /*}*/

    plat->process(plat,s,packet);
}

/* 
 *  Starts a listener on *address*. data is a generic pointer that will 
 *  be given to every callbacks used by libevent.
 */
void run (const int port, const net_platform_list *list )
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
    listener = evconnlistener_new_bind(ebase, accept_conn_cb, (void *)list,
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

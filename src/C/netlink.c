/*
 * Copyright (c) 2016 Technicolor Delivery Technologies, SAS
 *
 * The source code form of this lua-tch component is subject
 * to the terms of the Clear BSD license.
 *
 * You can redistribute it and/or modify it under the terms of the
 * Clear BSD License (http://directory.fsf.org/wiki/License:ClearBSD)
 *
 * See LICENSE file for more details.
 */

/**
 * Binding to receive netlink messages from the kernel.
 *
 * This module registers a lua callback function that will be called
 * on interface state changes broadcast from the kernel via netlink.
 * The module uses the uloop event loop to process the activity on
 * the netlink socket.
 * @module tch.netlink
 * @usage
 * local uloop = require("uloop")
 * local netlink=require("tch.netlink")
 * local nl,err = netlink.listen(function(dev,state) ... end)
 *
 * local netlink.remove_neigh("192.168.1.254", "48:51:21:18:fd:8d", "eth0")
 *
 * ...
 * uloop.run()
 */

#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <libubox/uloop.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "common.h"

#include "lua.h"
#include "lauxlib.h"

#define NETLINK_LOG(FMT, ...)      syslog(LOG_ERR, "[netlink] " FMT, ##__VA_ARGS__)

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP  0x10000
#endif

#define NETLINK_MT    "netlink"

// We need a unique key in the registry where the netlink code will store
// its bookkeeping data. Instead of creating a dummy static var whose
// address we use as a light userdata we can also simply reuse the
// luaopen_*() function pointer.
int luaopen_tch_netlink(lua_State *L);
#define NETLINK_KEY  luaopen_tch_netlink

struct event_socket {
	struct uloop_fd uloop;
	struct nl_sock *sock;
	int bufsize;
	lua_State *L;
};

struct neigh {
	struct ether_addr	ether_addr;
	int			af_family;
	union {
		struct in_addr	_addr4;
		struct in6_addr	_addr6;
	} u;
#define addr4	u._addr4
#define addr6	u._addr6
	unsigned int		if_index;
};

static void event_route_newlink(struct event_socket *ev, const char * ifname, int up);


/*
 * handle_uloop_event: uloop callback on socket activity.
 */
static void cb_uloop_event(struct uloop_fd *u, unsigned int events)
{
	struct event_socket *ev = container_of(u, struct event_socket, uloop);
	int err;
	socklen_t errlen = sizeof(err);

	if (!u->error) {
		(void)events;
		nl_recvmsgs_default(ev->sock);
		return;
	}

	if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &errlen))
		goto abort;

	switch(err) {
	case ENOBUFS:
		// Increase rx buffer size on netlink socket
		NETLINK_LOG("Catch NOBUF error, and perform DUMP");
		ev->bufsize *= 2;
		if (nl_socket_set_buffer_size(ev->sock, ev->bufsize, 0))
			goto abort;

		// Request full dump since some info got dropped
		struct rtgenmsg msg = { .rtgen_family = AF_UNSPEC };
		nl_send_simple(ev->sock, RTM_GETLINK, NLM_F_DUMP, &msg, sizeof(msg));
		break;

	default:
		goto abort;
	}
	u->error = false;
	return;

abort:
	uloop_fd_delete(&ev->uloop);
	return;
}

/*
 * cb_nl_event: callback to handle netlink messages.
 *
 * returns 0 to process more messages
 */
static int cb_nl_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct nlattr *nla[__IFLA_MAX];
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct event_socket *s = (struct event_socket *)arg;

	switch(nh->nlmsg_type) {
	case RTM_NEWLINK:
		nlmsg_parse(nh, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
		if (nla[IFLA_IFNAME])
			event_route_newlink(s, nla_data(nla[IFLA_IFNAME]), ifi->ifi_flags & IFF_LOWER_UP);
		break;

	default:
		break;
	}

	return 0;
}


/*
 * create_event_socket: create netlink socket and link to uloop
 *
 * returns 0 for success, -1 for failure.
 */
static int create_event_socket(struct event_socket *ev, const char **errmsg)
{
	memset(&ev->uloop, 0, sizeof(ev->uloop));
	ev->sock = nl_socket_alloc();
	if (!ev->sock) {
		*errmsg = "Failed to alloc socket";
		return -1;
	}

	if (nl_connect(ev->sock, 0)) {
		*errmsg = "nl_connect failed";
		goto err;
	}

	ev->uloop.fd = nl_socket_get_fd(ev->sock);
	ev->uloop.cb = cb_uloop_event;
	if (uloop_fd_add(&ev->uloop, ULOOP_READ | ULOOP_ERROR_CB)) {
		*errmsg = "Failed to add nl socket to uloop";
		goto err;
	}

	// Increase rx buffer size to 65K on event sockets
	ev->bufsize = 65535;
	if (nl_socket_set_buffer_size(ev->sock, ev->bufsize, 0)) {
		*errmsg = "Failed to set nl socket recv buffersize to 65K";
		goto err;
	}

	return 0;

err:
	nl_socket_free(ev->sock);
	ev->sock= NULL;
	return -1;
}

static int set_neigh_filter(const char *ip, const char *mac, const char *dev, struct neigh *filter)
{
	struct ether_addr	*pether_addr;

	memset(filter, 0, sizeof(struct neigh));

	/* ip address filter
	 */
	if (inet_pton(AF_INET, ip, &filter->addr4))
		filter->af_family = AF_INET;
	else if (inet_pton(AF_INET6, ip, &filter->addr6))
		filter->af_family = AF_INET6;
	else
		return -1;

	/* ethernet filter : do a copy because it is a static variable
	 */
	if ( (pether_addr = ether_aton(mac)) == NULL )
		return -2;
	memcpy(&filter->ether_addr, pether_addr, sizeof(filter->ether_addr));

	/* interface filter
	 */
	if ((filter->if_index = if_nametoindex(dev)) == 0)
		return -3;
	return 0;
}

/**
 * Set the given attribute in the nlmsghdr
 *
 * return 0 for success, -1 on failure
 */
static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen) {
	struct rtattr	*rta;
	int		len = RTA_LENGTH(alen);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > (unsigned)maxlen)
		return -1;

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
	rta = NLMSG_TAIL(n);

	rta->rta_type = type;
	rta->rta_len = len;

	memcpy(RTA_DATA(rta), data, alen);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

/**
 * Remove the neighbour entry (eg: ARP) in the table
 *
 * returns 0 for success, -1 for failure.
 */
static int remove_neigh(struct nl_sock *sk, const char *ip, const char *mac, const char *dev)
{
	struct neigh	filter;
	struct
	{
		struct nlmsghdr	n;
		struct ndmsg	ndm;
		char		buf[256];
	} req;

	if (set_neigh_filter(ip, mac, dev, &filter))
		return -1;

	req.n.nlmsg_type = RTM_DELNEIGH;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));

	req.ndm.ndm_family = filter.af_family;

	if (filter.af_family == AF_INET)
		addattr_l(&req.n, sizeof(req), NDA_DST, &filter.addr4, sizeof(filter.addr4));
	else /* AF_INET6 */
		addattr_l(&req.n, sizeof(req), NDA_DST, &filter.addr6, sizeof(filter.addr6));

	req.ndm.ndm_ifindex = filter.if_index;

	if (nl_sendto(sk, &req, sizeof(req)) < 0)
		return -1;

	return 0;
}


#define TO_EV_UDATA(idx)  (struct event_socket *)luaL_checkudata(L, idx, NETLINK_MT)

/*
 * garbage collect the event socket
 */
static int l_netlink_gc (lua_State *L)
{
	struct event_socket *ev = TO_EV_UDATA(1);

	if (ev->sock) {
		lua_pushlightuserdata(L, NETLINK_KEY);
		lua_rawget(L, LUA_REGISTRYINDEX); //

		// clear entry for this event socket
		lua_pushnil(L);
		lua_rawseti(L, -2, nl_socket_get_fd(ev->sock));

		uloop_fd_delete(&ev->uloop);
		nl_socket_free(ev->sock);
		ev->sock= NULL;
	}
	return 0;
}


static void event_route_newlink(struct event_socket *ev, const char * ifname, int up)
{
	lua_State *L= ev->L;

	lua_pushlightuserdata(L, NETLINK_KEY);
	lua_rawget(L, LUA_REGISTRYINDEX);

	// get callback for this event socket from the NETLINK_KEY table
	lua_rawgeti(L, -1, nl_socket_get_fd(ev->sock));

	if (lua_isfunction(L, -1)) {
		lua_pushstring(L, ifname);
		lua_pushboolean(L, up);
		if (lua_pcall(L, 2, 0, 0) != 0) {
			NETLINK_LOG("event callback failed: error=%s", lua_tostring(L, -1));
			lua_pop(L, 1);
		}
	} else {
		lua_pop(L, 1);
	}
}

/**
 * Create a new netlink object.
 *
 * @function listen
 * @param cb callback function(dev,state) called with device name and state
 * @treturn netlink The newly created object.
 * @error Error message.
 */
static int l_netlink_listen (lua_State *L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);

	const char *errmsg;
	struct event_socket *ev = (struct event_socket *)lua_newuserdata(L, sizeof(struct event_socket));

	luaL_getmetatable(L, NETLINK_MT);
	lua_setmetatable(L, -2);

	if (create_event_socket(ev, &errmsg)) {
		lua_pushnil(L);
		lua_pushstring(L, errmsg);
		return 2;
	}

	/* used in our callbacks */
	ev->L = L;

	// Install the valid custom callback handler
	nl_socket_modify_cb(ev->sock, NL_CB_VALID, NL_CB_CUSTOM, cb_nl_event, ev);

	// Disable sequence number checking on event sockets
	nl_socket_disable_seq_check(ev->sock);

	// Receive network link events form kernel
	nl_socket_add_membership(ev->sock, RTNLGRP_LINK);


	lua_pushlightuserdata(L, NETLINK_KEY);
	lua_rawget(L, LUA_REGISTRYINDEX);

	lua_pushvalue(L, 1); // copy callback fn on stack
	lua_rawseti(L, -2, nl_socket_get_fd(ev->sock));

	// remove callback mapping from stack
	lua_pop(L, 1);

	return 1;
}

/**
 * Remove the neighbour entry.
 *
 * @function remove_neigh
 * @param ip the IP address of the neighbour
 * @param mac the MAC address of the neighbour
 * @param dev the interface where the neighbour was discovered
 * @treturn boolean true
 * @error Error message.
 */
static int l_netlink_remove_neigh(lua_State *L)
{
	const char		*ip = luaL_checkstring(L, 1);
	const char		*mac = luaL_checkstring(L, 2);
	const char		*dev = luaL_checkstring(L, 3);
	struct nl_sock		*sk = NULL;
	const char		*msg;


	if ((sk = nl_socket_alloc()) == NULL) {
		msg = "nl_socket_alloc";
		goto err;
	}

	if (nl_connect(sk, NETLINK_ROUTE)) {
		msg = "nl_connect";
		goto err;
	}

	nl_socket_disable_seq_check(sk);

	if (remove_neigh(sk, ip, mac, dev)) {
		msg = "remove_neigh";
		goto err;
	}

	nl_socket_free(sk);

	lua_pushboolean(L, 1);

	return 1;

err:
	if (sk)
		nl_socket_free(sk);

	lua_pushnil(L);
	lua_pushstring(L, msg);

	return 2;
}

static const luaL_reg	s_tch_netlink [] =
{
	{"listen",		l_netlink_listen},
	{"remove_neigh",	l_netlink_remove_neigh},
	{NULL,			NULL}
};

LUALIB_API int luaopen_tch_netlink (lua_State *L)
{
	// construct metatable with the methods for our object
	luaL_newmetatable(L, NETLINK_MT);
	lua_pushcfunction(L, l_netlink_gc);
	lua_setfield(L, -2, "__gc");

	// create the callbacks table in the registry
	lua_pushlightuserdata(L, NETLINK_KEY);
	lua_newtable(L);
	lua_rawset(L, LUA_REGISTRYINDEX);

	lua_createtable(L, 0, ELEMS(s_tch_netlink));
	luaL_register(L, NULL, s_tch_netlink);

	return 1;
}

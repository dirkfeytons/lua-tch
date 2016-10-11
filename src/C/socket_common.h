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

#ifndef LUA_TCH_SOCKET_COMMON_H
#define LUA_TCH_SOCKET_COMMON_H

#include "common.h"

// maximum size of a datagram
// 33KB because a parameter value in TR-069 can be 32KB
// and we need some room for serialization overhead
#define MAX_DGRAM_SIZE 33792

// name of metatable for socket objects
#define SOCKET_UNIX_MT "socket.unix"

// socket object
typedef struct {
  int  sk;                    // socket descriptor
  char data[MAX_DGRAM_SIZE];  // buffer to store data read from socket or before sending
} sk_udata_t;

#define TO_SK_UDATA(idx)  (sk_udata_t *)luaL_checkudata(L, idx, SOCKET_UNIX_MT)

// A way to remove a socket from the evloop, e.g. because it is being closed.
HIDDEN void socket_evloop_remove_sk(lua_State *L, int sk);

// Close a socket, e.g. because the peer closed the connection and we detected
// that in evloop.
HIDDEN void socket_unix_sk_close(lua_State *L, int sk);

#endif  // LUA_TCH_SOCKET_COMMON_H

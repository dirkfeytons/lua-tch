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
 * Lua C module exposing Unix domain sockets.
 *
 * Currently implemented:
 *
 * - Datagram and stream sockets.
 * - The sockets are created with `SO_PASSCRED` option.
 * - All addresses are in the abstract namespace but the leading `\0` will
 *   be added automatically.
 * - Maximum size of datagrams is `MAX_DGRAM_SIZE` bytes.
 *
 * See @{unix(7)} for more information on Unix domain sockets.
 *
 * @module tch.socket.unix
 * @see unix(7)
 * @usage
 * Example server code:
 *   local unix = require("tch.socket.unix")
 *   local sk = unix.dgram()
 *   assert(sk:bind("myserveraddress"))
 *   while true do
 *     local data, from = sk:recvfrom()
 *     // process data and formulate response
 *     local response = process(data)
 *     sk:sendto(response, from)
 *   end
 *   sk:close()
 *
 * Example client code:
 *   local unix = require("tch.socket.unix")
 *   local sk = unix.dgram()
 *   assert(sk:connect("myserveraddress))
 *   local data = produce()
 *   sk:send(data)
 *   local response = sk:recv()
 *   process(response)
 *   sk:close()
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <assert.h>
#include "lua.h"
#include "lauxlib.h"
#include "common.h"
#include "socket_common.h"

#define UNIXSOCKET_LOG(FMT, ...)      syslog(LOG_ERR, "[socket.unix] " FMT, ##__VA_ARGS__)
#ifdef ENABLE_DEBUG
#define UNIXSOCKET_LOG_DBG(FMT, ...)  syslog(LOG_DEBUG, "[socket.unix] " FMT, ##__VA_ARGS__)
#else
#define UNIXSOCKET_LOG_DBG(FMT, ...)
#endif

// Version of SUN_LEN() for paths in abstract namespace.
// Only take the used part of the 'sun_path' field into account.
// Otherwise the trailing \0 bytes will also be part of the address,
// which gives funny output in /proc/net/unix.
// Assumes there's a 'path_len' variable containing the strlen of the path.
// The + 1 is for the leading \0.
#define ABSTRACT_SUN_LEN(ptr) ((socklen_t) offsetof(struct sockaddr_un,sun_path) \
                               + 1 + path_len)

// Calculates the size of the used part of the 'sun_path' field,
// excluding the leading \0, based on the size reported by recvfrom().
#define ABSTRACT_SUN_FROM_LEN(from_len) (from_len - 1 - (socklen_t) offsetof(struct sockaddr_un,sun_path))

static int open_socket(lua_State *L, int sk_type)
{
  int         err;
  int         opt = 1;
  // make sure to only allow options we support
  int         flags = luaL_optint(L, 1, 0) & (SOCK_NONBLOCK | SOCK_CLOEXEC);
  sk_udata_t *sk_udata = (sk_udata_t *)lua_newuserdata(L, sizeof(sk_udata_t));

  sk_udata->sk = socket(AF_UNIX, sk_type | flags, 0);
  if (sk_udata->sk == -1)
    goto error;
  luaL_getmetatable(L, SOCKET_UNIX_MT);
  lua_setmetatable(L, -2);
  if (setsockopt(sk_udata->sk, SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt)) != 0)
    goto error;

  return 1;

error:
  err = errno;  // save errno because subsequent code might do something that changes it
  lua_pushnil(L);
  lua_pushstring(L, strerror(err));
  return 2;
}

/**
 * Create a new datagram socket.
 *
 * The `SO_PASSCRED` socket option is always set.
 * @function dgram
 * @int flags Bitwise OR of the `SOCK_*` constants.
 * @treturn sk The newly created datagram socket.
 * @error Error message.
 */
static int l_dgram(lua_State *L)
{
  return open_socket(L, SOCK_DGRAM);
}

/**
 * Create a new stream socket.
 *
 * The `SO_PASSCRED` socket option is always set.
 * @function stream
 * @int flags Bitwise OR of the `SOCK_*` constants.
 * @treturn sk The newly created stream socket.
 * @error Error message.
 */
static int l_stream(lua_State *L)
{
  return open_socket(L, SOCK_STREAM);
}

/**
 * Unixsocket methods.
 * @type sk
 */

/**
 * Close the socket.
 *
 * Calling socket methods on the closed socket will result in errors.
 * It's not an error to close a socket more than once.
 * Closing a socket will automatically remove it from any event loop
 * it was added to but not removed yet.
 * @function sk:close
 */
static int l_sk_close(lua_State *L)
{
  sk_udata_t *sk_udata = TO_SK_UDATA(1);

  socket_unix_sk_close(L, sk_udata->sk);
  sk_udata->sk = -1;
  return 0;
}

// typedef for both the bind() and connect() functions
typedef int (*bind_connect_fn)(int, const struct sockaddr *, socklen_t);

// helper function that binds or connects a socket
static int sk_bind_connect(lua_State *L, bind_connect_fn fn)
{
  sk_udata_t         *sk_udata = TO_SK_UDATA(1);
  size_t              path_len;
  const char         *path = luaL_checklstring(L, 2, &path_len);
  struct sockaddr_un  addr = { .sun_family = AF_UNIX };

  // - 1 for the leading \0 we'll be adding
  if (path_len > sizeof(addr.sun_path) - 1)
  {
    lua_pushnil(L);
    lua_pushliteral(L, "path too long");
    return 2;
  }
  // + 1 because we do paths in the abstract namespace
  memcpy(addr.sun_path + 1, path, path_len);
  if (fn(sk_udata->sk, (struct sockaddr *)&addr, ABSTRACT_SUN_LEN(&addr)) != 0)
  {
    int err = errno;  // save errno because subsequent code might do something that changes it

    lua_pushnil(L);
    lua_pushstring(L, strerror(err));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Bind the socket to the given path in the abstract namespace.
 * The leading `\0` will be added automatically.
 * Can only be done once and before any data is sent.
 *
 * @function sk:bind
 * @string path The path in the abstract namespace to bind to.
 * @treturn boolean `true`
 * @error Error message.
 */
static int l_sk_bind(lua_State *L)
{
  return sk_bind_connect(L, bind);
}

/**
 * Connect the socket to the given path in the abstract namespace.
 * The leading `\0` will be added automatically.
 * Can be called multiple times.
 *
 * @function sk:connect
 * @string path The path in the abstract namespace to connect to.
 * @treturn boolean `true`
 * @error Error message.
 */
static int l_sk_connect(lua_State *L)
{
  return sk_bind_connect(L, connect);
}

/**
 * Mark the socket as a listening socket.
 *
 * @function sk:listen
 * @return boolean `true`
 * @error Error message.
 */
static int l_sk_listen(lua_State *L)
{
  sk_udata_t *sk_udata = TO_SK_UDATA(1);

  if (listen(sk_udata->sk, SOMAXCONN) != 0)
  {
    int err = errno;  // save errno because subsequent code might do something that changes it

    lua_pushnil(L);
    lua_pushstring(L, strerror(err));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Accept a new connection.
 *
 * @function sk:accept
 * @int flags Bitwise OR of the `SOCK_*` constants.
 * @treturn sk New socket representing the accepted connection.
 * @error Error message. In particular, if the socket is marked non-blocking
 *   and the operation would block then the message `"WOULDBLOCK"` is returned.
 */
static int l_sk_accept(lua_State *L)
{
  sk_udata_t *sk_udata = TO_SK_UDATA(1);
  // make sure to only allow options we support
  int         flags = luaL_optint(L, 2, 0) & (SOCK_NONBLOCK | SOCK_CLOEXEC);
  int         conn_sk;

  // TODO: support returning peer address
  conn_sk = accept4(sk_udata->sk, NULL, NULL, flags);
  if (conn_sk == -1)
  {
    const char *errmsg;

    if (errno == EAGAIN || errno == EWOULDBLOCK)
      errmsg = "WOULDBLOCK";
    else
      errmsg = strerror(errno);
    lua_pushnil(L);
    lua_pushstring(L, errmsg);
    return 2;
  }
  sk_udata = (sk_udata_t *)lua_newuserdata(L, sizeof(sk_udata_t));
  luaL_getmetatable(L, SOCKET_UNIX_MT);
  lua_setmetatable(L, -2);
  sk_udata->sk = conn_sk;
  return 1;
}

// Helper function that supports both send() and sendto().
static int sk_sendto(lua_State *L, bool with_to)
{
  sk_udata_t         *sk_udata = TO_SK_UDATA(1);
  ssize_t             sent;
  size_t              data_len;
  const char         *data;
  socklen_t           to_len = 0;
  struct sockaddr_un  to = { .sun_family = AF_UNIX };
  struct sockaddr_un *p_to = NULL;
  const char         *errmsg = NULL;

  // construct destination address, if needed
  if (with_to)
  {
    size_t      path_len;
    const char *path = luaL_checklstring(L, 3, &path_len);

    // - 1 for the leading \0 we'll be adding
    if (path_len > sizeof(to.sun_path) - 1)
    {
      errmsg = "path too long";
      goto error;
    }
    // + 1 because we do paths in the abstract namespace
    memcpy(to.sun_path + 1, path, path_len);
    p_to = &to;
    to_len = ABSTRACT_SUN_LEN(p_to);
  }
  // check if the data is provided in a table
  if (lua_istable(L, 2))
  {
    // go over the strings in the table and copy them to the data buffer
    // note that even though the string is zero-terminated we do not
    // copy that zero in the buffer
    size_t  data_items = lua_objlen(L, 2);
    size_t  i;
    char   *p = sk_udata->data;

    data_len = 0;
    for (i = 1; i <= data_items; i++)
    {
      size_t      len;
      const char *data_item;

      lua_rawgeti(L, 2, i);
      data_item = luaL_checklstring(L, -1, &len);
      if ((data_len + len) > MAX_DGRAM_SIZE)
      {
        errmsg = "too much data";
        goto error;
      }
      memcpy(p, data_item, len);
      data_len += len;
      p += len;
      lua_pop(L, 1);
    }
    data = sk_udata->data;
  }
  else
  {
    data = luaL_checklstring(L, 2, &data_len);
    if (data_len > MAX_DGRAM_SIZE)
    {
      errmsg = "too much data";
      goto error;
    }
  }
restart:
  // sendto() with the last two arguments set to NULL and 0 is equivalent to send()
  sent = sendto(sk_udata->sk, data, data_len, 0, (struct sockaddr *)p_to, to_len);
  if (sent == -1)
  {
    if (errno == EINTR)
      goto restart;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      errmsg = "WOULDBLOCK";
    else
      errmsg = strerror(errno);
    goto error;
  }
  else if (sent < (ssize_t)data_len)
  {
    // shouldn't happen with dgrams
    errmsg = "couldn't send all data";
    goto error;
  }
  lua_pushboolean(L, 1);
  return 1;

error:
  lua_pushnil(L);
  lua_pushstring(L, errmsg);
  return 2;
}

/**
 * Send the given data to the peer to which the socket is connected.
 * This means `sk:connect` must have been called first.
 * The data can be provided as a string or as an array of strings.
 * If the total size of the data is more than `MAX_DGRAM_SIZE` an
 * error will be returned.
 *
 * @function sk:send
 * @tparam string|{string,...} data The data to send.
 * @treturn boolean `true`
 * @error Error message. In particular, if the socket is marked non-blocking
 *   and the operation would block then the message `"WOULDBLOCK"` is returned.
 */
static int l_sk_send(lua_State *L)
{
  return sk_sendto(L, false);
}

/**
 * Send the given data to the given path in the abstract namespace.
 * The leading `\0` will be added automatically.
 * The data can be provided as a string or as an array of strings.
 * If the total size of the data is more than `MAX_DGRAM_SIZE` an
 * error will be returned.
 *
 * @function sk:sendto
 * @tparam string|{string,...} data The data to send.
 * @string path The path in the abstract namespace to send the data to.
 * @treturn boolean `true`
 * @error Error message. In particular, if the socket is marked non-blocking
 *   and the operation would block then the message `"WOULDBLOCK"` is returned.
 */
static int l_sk_sendto(lua_State *L)
{
  return sk_sendto(L, true);
}

// Helper function that supports both recv() and recvfrom().
static int sk_recvfrom(lua_State *L, bool want_from)
{
  sk_udata_t         *sk_udata = TO_SK_UDATA(1);
  ssize_t             received;
  struct sockaddr_un  from;
  socklen_t           from_len = sizeof(from);
  struct sockaddr_un *p_from = want_from ? &from : NULL;
  socklen_t          *p_from_len = want_from ? &from_len : NULL;

restart:
  received = recvfrom(sk_udata->sk, sk_udata->data, sizeof(sk_udata->data), 0,
      (struct sockaddr *)p_from, p_from_len);
  if (received == -1)
  {
    int err = errno;  // save errno because subsequent code might do something that changes it

    if (err == EINTR)
      goto restart;
    lua_pushnil(L);
    if (err == EAGAIN || err == EWOULDBLOCK)
      lua_pushliteral(L, "WOULDBLOCK");
    else
      lua_pushstring(L, strerror(err));
    return 2;
  }
  lua_pushlstring(L, sk_udata->data, received);
  if (want_from)
  {
    // + 1 because we don't include the leading \0
    lua_pushlstring(L, from.sun_path + 1, ABSTRACT_SUN_FROM_LEN(from_len));
    return 2;
  }
  return 1;
}

/**
 * Receive data from the socket.
 *
 * @function sk:recv
 * @treturn string The data read from the socket.
 * @error Error message. In particular, if the socket is marked non-blocking
 *   and the operation would block then the message `"WOULDBLOCK"` is returned.
 */
static int l_sk_recv(lua_State *L)
{
  return sk_recvfrom(L, false);
}

/**
 * Receive data from the socket and the address of the sender.
 *
 * @function sk:recvfrom
 * @treturn string The data read from the socket.
 * @treturn string The path in the abstract namespace (without leading `\0`)
 *   of the sender. Note that this can be an empty string if the sender
 *   didn't bind its socket and the kernel didn't automatically generate
 *   an address (like it does when e.g. the `SO_PASSCRED` option is set).
 * @error Error message. In particular, if the socket is marked non-blocking
 *   and the operation would block then the message `"WOULDBLOCK"` is returned.
 */
static int l_sk_recvfrom(lua_State *L)
{
  return sk_recvfrom(L, true);
}

/**
 * Return the underlying file descriptor of this socket.
 *
 * @function sk:fd
 * @treturn int The file descriptor.
 */
static int l_sk_fd(lua_State *L)
{
  sk_udata_t *sk_udata = TO_SK_UDATA(1);

  lua_pushinteger(L, sk_udata->sk);
  return 1;
}

// Methods on a socket object.
static const luaL_reg s_sk_methods[] = {
  { "__gc",     l_sk_close    },
  { "close",    l_sk_close    },
  { "bind",     l_sk_bind     },
  { "connect",  l_sk_connect  },
  { "listen",   l_sk_listen   },
  { "accept",   l_sk_accept   },
  { "send",     l_sk_send     },
  { "sendto",   l_sk_sendto   },
  { "recv",     l_sk_recv     },
  { "recvfrom", l_sk_recvfrom },
  { "fd",       l_sk_fd       },
  { NULL,       NULL          }
};

// Public functions in our module.
static const luaL_reg s_unixsocket[] = {
  { "dgram",   l_dgram  },
  { "stream",  l_stream },
  { NULL,      NULL     }
};

/**
 * Useful constants.
 * @field MAX_DGRAM_SIZE The maximum size of a datagram, in bytes.
 * @field SOCK_CLOEXEC Option to close the socket across `execve()`.
 * @field SOCK_NONBLOCK Option to make the socket non-blocking when invoking `dgram` or `stream`.
 * @table tch.socket.unix
 */
static const ConstantEntry s_constants[] =
{
  CONSTANT(MAX_DGRAM_SIZE),
  CONSTANT(SOCK_CLOEXEC),
  CONSTANT(SOCK_NONBLOCK),
  { NULL, 0 }
};

int luaopen_tch_socket_unix(lua_State *L)
{
  const ConstantEntry *c;

  // construct metatable with the methods for a socket object
  // and that is at the same time used as userdata tag
  luaL_newmetatable(L, SOCKET_UNIX_MT);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  luaL_register(L, NULL, s_sk_methods);
  // create our module; note that we don't register a global variable!
  lua_createtable(L, 0, ELEMS(s_unixsocket) + ELEMS(s_constants));
  luaL_register(L, NULL, s_unixsocket);
  for (c = s_constants; c->name; c++)
  {
    lua_pushstring(L, c->name);
    lua_pushinteger(L, c->value);
    lua_rawset(L, -3);
  }
  return 1;
}

void socket_unix_sk_close(lua_State *L, int sk)
{
  if (sk != -1)
  {
    // remove socket from evloop when needed
    socket_evloop_remove_sk(L, sk);
    // now close the socket
    close(sk);
  }
}

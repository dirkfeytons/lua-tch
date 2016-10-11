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
 * Lua C module exposing event loops.
 *
 * See @{epoll(7)} for more information on event loops.
 *
 * @module tch.socket.evloop
 * @see tch.socket.unix
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
#include <sys/epoll.h>
#include <unistd.h>
#include <assert.h>
#include "lua.h"
#include "lauxlib.h"
#include "socket_common.h"

#define EVLOOP_LOG(FMT, ...)      syslog(LOG_ERR, "[socket.evloop] " FMT, ##__VA_ARGS__)
#ifdef ENABLE_DEBUG
#define EVLOOP_LOG_DBG(FMT, ...)  syslog(LOG_DEBUG, "[socket.evloop] " FMT, ##__VA_ARGS__)
#else
#define EVLOOP_LOG_DBG(FMT, ...)
#endif

// name of metatable for event loop objects
#define EVLOOP_MT    "socket.evloop"

// We need a unique key in the registry where the evloop code will store
// its bookkeeping data. Instead of creating a dummy static var whose
// address we use as a light userdata we can also simply reuse the
// luaopen_*() function pointer.
int luaopen_tch_socket_evloop(lua_State *L);
#define EVLOOP_KEY  luaopen_tch_socket_evloop

/**
 * Create a new event loop.
 *
 * @function evloop
 * @treturn evloop The newly created event loop.
 * @error Error message.
 * @see evloop:close
 */
static int l_evloop(lua_State *L)
{
  int  err;
  int *epfd = (int *)lua_newuserdata(L, sizeof(int));

  *epfd = epoll_create1(EPOLL_CLOEXEC);
  if (*epfd == -1)
    goto error;
  luaL_getmetatable(L, EVLOOP_MT);
  lua_setmetatable(L, -2);
  // also create empty table for the callbacks in the evloop
  // table in the registry
  lua_pushlightuserdata(L, EVLOOP_KEY);
  lua_rawget(L, LUA_REGISTRYINDEX);
  lua_newtable(L);
  lua_rawseti(L, -2, *epfd);
  lua_pop(L, 1); // pop the evloop table
  return 1;

error:
  err = errno;
  lua_pushnil(L);
  lua_pushstring(L, strerror(err));
  return 2;
}

/**
 * Event loop methods.
 * @type evloop
 */

#define TO_EPFD()  *((int *)luaL_checkudata(L, 1, EVLOOP_MT))
// maximum number of events we will process in each epoll_wait() call
#define MAX_EPOLL_EVENTS  10
// For each socket in each evloop instance we keep an array with
// data we need to process an event for that socket.
// An array is used for slightly faster lookup performance.
// The defines make it more readable to see which data we're accessing.
#define IDX_SK_UDATA  1
#define IDX_READ_CB   2
#define IDX_WRITE_CB  3
#define IDX_MAX       IDX_WRITE_CB

/**
 * Close this event loop.
 *
 * Calling other methods on a closed event loop will result in errors.
 * It's not an error to close an event loop more than once.
 * Closing the event loop from one of your event callbacks will cause
 * `Evloop:run` to return.
 * @function evloop:close
 * @see evloop:run
 */
static int l_evloop_close(lua_State *L)
{
  int *p_epfd = (int *)luaL_checkudata(L, 1, EVLOOP_MT);

  if (*p_epfd != -1)
  {
    // remove the table with callbacks for this evloop
    lua_pushlightuserdata(L, EVLOOP_KEY);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushnil(L);
    lua_rawseti(L, -2, *p_epfd);
    // now close the epoll instance
    close(*p_epfd);
    *p_epfd = -1;
  }
  return 0;
}

/**
 * Add a socket to this event loop with the given callback(s).
 *
 * Based on which callbacks are provided the socket will be
 * monitored for the corresponding event type.
 * At least one callback must be provided.
 * Adding an already added socket is currently not supported.
 * @function evloop:add
 * @tparam sk|int sk The socket or raw file descriptor to add
 *   to the event loop.
 * @func[opt] read_cb Callback function that will be called when
 *   the socket has data ready to be read. The callback will be
 *   called with two arguments: the event loop object and the
 *   socket object or raw file descriptor.
 * @func[opt] write_cb Callback function that will be called when
 *   the socket is ready to send more data. The callback will be
 *   called with two arguments: the event loop object and the
 *   socket object or raw file descriptor.
 * @treturn boolean true
 * @error Error message.
 */
static int l_evloop_add(lua_State *L)
{
  int                 err;
  int                 type2 = lua_type(L, 2);
  int                 type3, type4;
  int                 epfd= TO_EPFD();
  struct epoll_event  event = { .events = 0 };
  int                 fd;

  if (type2 == LUA_TNUMBER)
    fd = (int)lua_tointeger(L, 2);
  else if (type2 == LUA_TUSERDATA)
  {
    sk_udata_t *sk_udata = TO_SK_UDATA(2);
    fd = sk_udata->sk;
  }
  else
    return luaL_typerror(L, 2, "int or tch.socket");

  EVLOOP_LOG_DBG("adding sk %d to evloop %d", fd, epfd);
  event.data.fd = fd;
  // check that either a callback or nothing was provided
  type3 = lua_type(L, 3);
  if (type3 == LUA_TFUNCTION)
    event.events |= EPOLLIN;
  else
    luaL_argcheck(L, (type3 == LUA_TNONE || type3 == LUA_TNIL), 3, "expected nil or function");
  type4 = lua_type(L, 4);
  if (type4 == LUA_TFUNCTION)
    event.events |= EPOLLOUT;
  else
    luaL_argcheck(L, (type4 == LUA_TNONE || type4 == LUA_TNIL), 4, "expected nil or function");
  // specifying no callbacks is not allowed obviously
  if (event.events == 0)
    return luaL_error(L, "no callbacks given");
  // Edge-triggered or level-triggered epoll behavior?
  // ET requires the user to read/write in the callback until WOULDBLOCK
  // is returned, otherwise it might never get another event (as explained
  // in the epoll(7) man page). If an error is thrown in the Lua code that
  // causes it to not read until WOULDBLOCK the code hangs, which is
  // something that can always happen, no matter how robust we try to code.
  // Let's keep things simple and stay with the default level-triggered
  // behavior, even if it might be less performant...
  //event.events |= EPOLLET;
  // Also register for EPOLLRDHUP so we can detect if the peer of a stream
  // connection closed the connection. In that case we remove the socket from
  // the epoll instance because on the next epoll_wait() it will be signaled
  // as ready again and that might lead to an infinite loop.
  event.events |= EPOLLRDHUP;
  // add the socket to the epoll instance
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) < 0)
    goto error;
  // store the sk_udata and callbacks for later use
  lua_pushlightuserdata(L, EVLOOP_KEY);
  lua_rawget(L, LUA_REGISTRYINDEX);
  lua_rawgeti(L, -1, epfd);
  lua_createtable(L, IDX_MAX, 0);
  lua_pushvalue(L, -1); // save a copy of the table to fill it
  lua_rawseti(L, -3, fd);
  lua_pushvalue(L, 2);  // copy the sk_udata or raw fd to use as value
  lua_rawseti(L, -2, IDX_SK_UDATA);
  if (type3 == LUA_TFUNCTION)
  {
    lua_pushvalue(L, 3); // copy the read callback to use as value
    lua_rawseti(L, -2, IDX_READ_CB);
  }
  if (type4 == LUA_TFUNCTION)
  {
    lua_pushvalue(L, 4); // copy the write callback to use as value
    lua_rawseti(L, -2, IDX_WRITE_CB);
  }
  lua_pushboolean(L, 1);
  return 1;

error:
  err = errno;
  lua_pushnil(L);
  lua_pushstring(L, strerror(err));
  return 2;
}

/**
 * Remove the given socket or raw file descriptor from
 * this event loop.
 *
 * Trying to remove a socket that is not in this event loop
 * will currently result in an error. However, removing a
 * closed socket from this event loop will always succeed.
 * @function evloop:remove
 * @tparam sk|int sk The socket or raw file descriptor to
 *   remove from the event loop.
 * @treturn boolean true
 * @error Error message.
 */
static int l_evloop_remove(lua_State *L)
{
  int err;
  int epfd = TO_EPFD();
  int type2 = lua_type(L, 2);
  int fd;

  if (type2 == LUA_TNUMBER)
    fd = (int)lua_tointeger(L, 2);
  else if (type2 == LUA_TUSERDATA)
  {
    sk_udata_t *sk_udata = TO_SK_UDATA(2);
    fd = sk_udata->sk;
  }
  else
    return luaL_typerror(L, 2, "int or tch.socket");
  EVLOOP_LOG_DBG("removing sk %d to evloop %d\n", fd, epfd);
  // trying to remove a closed socket is a no-op
  if (fd != -1)
  {
    // remove from epoll instance
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) < 0)
      goto error;
    // remove callback(s)
    lua_pushlightuserdata(L, EVLOOP_KEY);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_rawgeti(L, -1, epfd);
    lua_pushnil(L);
    lua_rawseti(L, -2, fd);
  }
  lua_pushboolean(L, 1);
  return 1;

error:
  err = errno;
  lua_pushnil(L);
  lua_pushstring(L, strerror(err));
  return 2;
}

static void loc_process_event(lua_State *L, int sk, int idx_cb)
{
  int ret;

  // retrieve event callback
  lua_rawgeti(L, 3, idx_cb);
  // because we get an event we must have provided a corresponding
  // callback when the socket was added to the evloop so we must
  // have a callback now on the stack
  assert(lua_type(L, -1) == LUA_TFUNCTION);
  // push the arguments
  lua_pushvalue(L, 1); // arg1: the evloop itself
  lua_rawgeti(L, 3, IDX_SK_UDATA); // arg2: the socket userdata
  assert(lua_type(L, -1) == LUA_TUSERDATA || lua_type(L, -1) == LUA_TNUMBER);
  // TODO: pass an error handler function to get better error message
  ret = lua_pcall(L, 2, 0, 0);
  if (ret != 0)
  {
    // Note that if the callback failed and it didn't consume
    // the data the next epoll_wait() call will return with
    // another event for the socket. We could end up with an
    // endless loop. To prevent this we could remove the socket
    // from the event loop when the callback failed but perhaps
    // that would hide the issue.
    EVLOOP_LOG("event callback failed: idx_cb=%d, sk=%d, error=%s", idx_cb, sk, lua_tostring(L, -1));
    lua_pop(L, 1);
  }
}

/**
 * Run this event loop.
 *
 * Once started it will wait for events on the sockets added to this
 * event loop and invoke the appropriate callback functions.
 * Running an empty event loop will return immediately with no error.
 * To break out of the event loop one of the callback functions must
 * call `evloop:close`.
 * @function evloop:run
 * @treturn boolean true
 * @error Error message.
 * @see evloop:close
 */
static int l_evloop_run(lua_State *L)
{
  int                 err;
  struct epoll_event  events[MAX_EPOLL_EVENTS]; // TODO: perhaps move this in a struct with epfd?
  int                *p_epfd = (int *)luaL_checkudata(L, 1, EVLOOP_MT);

  // fetch the callbacks table for this evloop
  lua_settop(L, 1); // make sure the stack only contains the evloop udata
  lua_pushlightuserdata(L, EVLOOP_KEY);
  lua_rawget(L, LUA_REGISTRYINDEX);
  lua_rawgeti(L, -1, *p_epfd);
  lua_replace(L, 2); // move this evloop's callbacks table one down to stack index 2

  // run event loop until it is closed or becomes empty
  // (calling epoll_wait() on an empty set hangs indefinitely)
  while (*p_epfd != -1)
  {
    int i;
    int ready;

    lua_pushnil(L);
    if (lua_next(L, 2) == 0)
      break;
    else
      lua_pop(L, 2);
    ready = epoll_wait(*p_epfd, events, MAX_EPOLL_EVENTS, -1);
    EVLOOP_LOG_DBG("epoll_wait() returned %d", ready);
    if (ready < 0)
    {
      // if we were interrupted then just restart
      if (errno == EINTR)
      {
        EVLOOP_LOG_DBG("epoll_wait interrupted");
        continue;
      }
      // for all other errors bail out
      goto error;
    }
    // process events
    for (i = 0; i < ready; i++)
    {
      struct epoll_event *event = &events[i];
      int                 sk = event->data.fd;

      EVLOOP_LOG_DBG("event=%d, sk=%d, eventmask=%x", i, sk, event->events);
      // fetch callbacks table for this socket
      lua_rawgeti(L, 2, sk);
      // Did we find it? Normally we can only receive events
      // for sockets that were added to the event loop and thus
      // have an entry in the table. However, somebody could
      // in its callback remove sockets from the event loop for
      // which we still need to process an event in this loop.
      // This will probably never happen but better safe than sorry.
      // If they do that then the socket should have been removed
      // from the evloop as well so we don't get the event again
      // in the next call to epoll_wait(). For extra robustness
      // we could try to remove the socket from the evloop here
      // as well but that's a TODO for now.
      if (lua_type(L, -1) == LUA_TNIL)
      {
        lua_pop(L, 1);
        continue;
      }

      // read event?
      if (event->events & EPOLLIN)
        loc_process_event(L, sk, IDX_READ_CB);
      // write event?
      if (event->events & EPOLLOUT)
        loc_process_event(L, sk, IDX_WRITE_CB);
      // error event?
      if (event->events & EPOLLERR)
      {
        socklen_t errlen = sizeof(err);

        if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0)
          EVLOOP_LOG("evloop error: sk=%d, error=%s", sk, strerror(err));
        // TODO: invoke error callback & remove socket from evloop?
      }
      // peer hung up?
      if (event->events & EPOLLRDHUP)
      {
        EVLOOP_LOG_DBG("peer hung up");
        socket_unix_sk_close(L, sk);
      }
      // restore stack so only the evloop itself and the callbacks table remain
      lua_settop(L, 2);
    }
  }

  lua_pushboolean(L, 1);
  return 1;

error:
  // we shouldn't be able to end up here
  err = errno;
  lua_pushnil(L);
  lua_pushstring(L, strerror(err));
  return 2;
}

/**
 * Return the underlying file descriptor of this event loop.
 *
 * @function evloop:fd
 * @treturn int The file descriptor.
 */
static int l_evloop_fd(lua_State *L)
{
  int epfd = TO_EPFD();

  lua_pushinteger(L, epfd);
  return 1;
}

// Methods on an event loop object.
static const luaL_reg s_evloop_methods[] = {
  { "__gc",   l_evloop_close  },
  { "close",  l_evloop_close  },
  { "add",    l_evloop_add    },
  { "remove", l_evloop_remove },
  { "run",    l_evloop_run    },
  { "fd",     l_evloop_fd     },
  { NULL, NULL }
};

// Public functions in our module.
static const luaL_reg s_evloop[] = {
  { "evloop",  l_evloop },
  { NULL,      NULL     }
};

int luaopen_tch_socket_evloop(lua_State *L)
{
  // construct metatable with the methods for an event loop
  // and that is at the same time used as userdata tag
  luaL_newmetatable(L, EVLOOP_MT);
  lua_pushvalue (L, -1);
  lua_setfield(L, -2, "__index");
  luaL_register(L, NULL, s_evloop_methods);
  // create the evloop callbacks table in the registry
  lua_pushlightuserdata(L, EVLOOP_KEY);
  lua_newtable(L);
  lua_rawset(L, LUA_REGISTRYINDEX);
  // create our module; note that we don't register a global variable!
  lua_createtable(L, 0, ELEMS(s_evloop));
  luaL_register(L, NULL, s_evloop);
  return 1;
}

void socket_evloop_remove_sk(lua_State *L, int sk)
{
  // remove evloop bookkeeping data for this socket
  lua_pushlightuserdata(L, EVLOOP_KEY);
  lua_rawget(L, LUA_REGISTRYINDEX);
  if (!lua_isnil(L, -1))
  {
    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
      lua_pushnil(L);
      lua_rawseti(L, -2, sk);
      lua_pop(L, 1);
    }
  }
}

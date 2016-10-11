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
 * Lua C module exposing timers that notify via file descriptors.
 *
 * See @{timerfd_create(2)} for more information on timers that notify via file descriptors.
 *
 * @module tch.timerfd
 *
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include "lua.h"
#include "lauxlib.h"
#include "common.h"

/**
 * Create a new timer_fd.
 *
 * @function create
 * @treturn timer_fd The new timer_fd.
 * @error Error message
 */
static int l_timerfd_create(lua_State *L)
{
  int         err;
  clockid_t   clk_id = CLOCK_MONOTONIC;
  int         *tfd = (int *)lua_newuserdata(L, sizeof(int));

  *tfd = timerfd_create(clk_id, (TFD_CLOEXEC | TFD_NONBLOCK));
  if (*tfd == -1)
  {
    goto error;
  }
  return 1;

error:
  err = errno;
  return luaL_error(L, "Failed to create timerfd: %s", strerror(err));
}

/**
 * Set the timing behaviour on a given timer_fd. Both the interval
 * and the first deadline are set to the given value, effectively creating
 * a periodic timer.
 *
 * @function settime
 * @param timer_fd A timer_fd struct.
 * @param secs How many seconds the timer should use.
 * @error Error message
 */
static int l_timerfd_settime(lua_State *L)
{
  int        err;
  int        *tfd = (int *) lua_touserdata(L, 1);
  time_t     secs = (int) luaL_checkint(L, 2);
  struct     itimerspec ts;

  if (tfd == NULL)
  {
    goto error;
  }
  ts.it_interval.tv_sec = secs;
  ts.it_interval.tv_nsec = 0;
  ts.it_value.tv_sec = secs;
  ts.it_value.tv_nsec = 0;
  if (timerfd_settime(*tfd, 0, &ts, NULL) == 0)
  {
    return 0;
  }

error:
  err = errno;
  return luaL_error(L, "Failed to set timerfd: %s", strerror(err));
}

/**
 * Return the underlying file descriptor of a timer_fd.
 *
 * @function fd
 * @param timer_fd A timer_fd struct.
 * @treturn int The file descriptor.
 * @error Error message
 */
static int l_timerfd_fd(lua_State *L)
{
  int err;
  int *tfd = (int *) lua_touserdata(L, 1);

  if (tfd == NULL)
  {
    goto error;
  }

  lua_pushinteger(L, *tfd);
  return 1;

error:
  err = errno;
  return luaL_error(L, "Failed to retrieve fd from timerfd: %s", strerror(err));
}

/**
 * Read from the underlying file descriptor of a timer_fd.
 *
 * @function read
 * @param fd An underlying file descriptor of a timer_fd.
 * @treturn int How many times the timer has fired since the last time we've read from it.
 * @error Error message
 */
static int l_timerfd_read(lua_State *L)
{
  int        err;
  int        tfd = (int) luaL_checkint(L, 1);
  uint64_t   missed;
  int        ret;

  /* Wait for the next timer event. If we have missed any the
   *    number is written to "missed" */
  ret = read (tfd, &missed, sizeof (missed));
  if (ret >= 0)
  {
    lua_pushinteger(L, missed);
    return 1;
  }
  err = errno;
  return luaL_error(L, "Failed to read timerfd: %s", strerror(err));
}

/**
 * Close the underlying file descriptor of a timer_fd. By closing the
 * underlying file descriptor, the timer should be disarmed and its
 * resources freed by the kernel.
 *
 * @function close
 * @param fd An underlying file descriptor of a timer_fd.
 * @error Error message
 */
static int l_timerfd_close(lua_State *L)
{
  int        err;
  int        tfd = (int) luaL_checkint(L, 1);
  int        ret;

  ret = close(tfd);
  if (ret == 0)
  {
    return 0;
  }
  err = errno;
  return luaL_error(L, "Failed to close timerfd: %s", strerror(err));
}

static const luaL_reg s_tch_timerfd[] =
{
  { "create", l_timerfd_create },
  { "settime", l_timerfd_settime },
  { "fd", l_timerfd_fd },
  { "read", l_timerfd_read},
  { "close", l_timerfd_close},
  { NULL, NULL }
};

int luaopen_tch_timerfd(lua_State *L)
{
  lua_createtable(L, 0, ELEMS(s_tch_timerfd));
  luaL_register(L, NULL, s_tch_timerfd);

  return 1;
}

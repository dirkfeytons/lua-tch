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
 * Bindings to POSIX functions and useful wrappers around them.
 * @module tch.posix
 */

#include <time.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <lua.h>
#include <lauxlib.h>
#include <pwd.h>
#include "common.h"

/**
 * Retrieve time using the given clock ID.
 *
 * @function clock_gettime
 * @param clk_id Clock ID, one of the `CLOCK_*` constants.
 * @treturn number The number of seconds on the clock.
 * @treturn number The number of nanoseconds on the clock.
 * @raise Throws in case of an invalid clock ID.
 * @see clock_elapsed
 * @see clock_gettime(2)
 */
static int l_clock_gettime(lua_State *L)
{
  struct timespec ts;
  clockid_t       clk_id = luaL_checkint(L, 1);

  if (clock_gettime(clk_id, &ts) != 0)
    return luaL_error(L, "%s: %s", "clock_gettime", strerror(errno));
  lua_pushnumber(L, ts.tv_sec);
  lua_pushnumber(L, ts.tv_nsec);
  return 2;
}

/**
 * Calculate the elapsed time since the given timestamp.
 *
 * @function clock_elapsed
 * @param clk_id Clock ID, one of the `CLOCK_*` constants. It's your
 *   responsibility to pass the same clock ID as used to generate the
 *   initial timestamp.
 * @number sec The number of seconds of the initial timestamp.
 * @number[opt] nsec The number of nanoseconds of the initial timestamp.
 *   If absent then elapsed time will be calculated based on the seconds
 *   part only.
 * @treturn number The number of microseconds elapsed between the initial
 *   timestamp and now.
 * @raise Throws in case of an invalid clock ID or `sec`/`nsec` not
 *   being numbers.
 * @see clock_gettime
 */
static int l_clock_elapsed(lua_State *L)
{
  struct timespec new_ts;
  lua_Number      total;
  clockid_t       clk_id = luaL_checkint(L, 1);
  lua_Number      old_sec = luaL_checknumber(L, 2);
  lua_Number      old_nsec = luaL_optnumber(L, 3, -1);

  if (clock_gettime(clk_id, &new_ts) != 0)
    return luaL_error(L, "%s: %s", "clock_elapsed", strerror(errno));

  if (new_ts.tv_nsec < old_nsec)
  {
    new_ts.tv_sec--;
    new_ts.tv_nsec += 1000000000L;
  }
  total = ((new_ts.tv_sec - old_sec) * 1000000);
  if (old_nsec >= 0)
    total += ((new_ts.tv_nsec - old_nsec) / 1000);
  lua_pushnumber(L, total);
  return 1;
}


/***
 * Get configuration information at runtime.
 * @function sysconf
 * @param int any valid sysconf value is accepted but only _SC_CLK_TCK is exported by the module.
 * @treturn int associated system configuration value
 * @see sysconf(3)
*/
static int l_sysconf(lua_State *L)
{
   lua_Integer d = lua_tointeger(L, 1);
   if (d == 0 && !lua_isinteger(L, 1))
     luaL_error(L, "%s: %s", "sysconf", strerror(errno));
   lua_pushinteger(L, sysconf(d));
   return 1;
}

/**
 * Retrieve statistics of the mounted file system on which the given path resides.
 *
 * @function statvfs
 * @string path A pathname whose underlying filesystem the statistics will be retrieved from.
 * @treturn table All the fields of the `struct statvfs` are the keys; the values are numbers.
 * @raise Throws in case of an invalid path.
 * @see statvfs(2)
 */
static int l_statvfs(lua_State *L)
{
  const char *path = luaL_checkstring(L, 1);
  struct statvfs info;
  memset(&info, 0, sizeof(struct statvfs));

  if (statvfs(path, &info) != 0) {
    return luaL_error(L, "%s(%s): %s", "statvfs", path, strerror(errno));
  }

    /* creates a table if none is given */
  lua_createtable (L, 0, 11);

  lua_pushliteral(L, "f_bsize");
  lua_pushnumber(L, info.f_bsize);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_frsize");
  lua_pushnumber(L, info.f_frsize);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_blocks");
  lua_pushnumber(L, info.f_blocks);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_bfree");
  lua_pushnumber(L, info.f_bfree);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_bavail");
  lua_pushnumber(L, info.f_bavail);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_files");
  lua_pushnumber(L, info.f_files);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_ffree");
  lua_pushnumber(L, info.f_ffree);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_favail");
  lua_pushnumber(L, info.f_favail);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_fsid");
  lua_pushnumber(L, info.f_fsid);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_flag");
  lua_pushnumber(L, info.f_flag);
  lua_rawset(L, -3);
  lua_pushliteral(L, "f_namemax");
  lua_pushnumber(L, info.f_namemax);
  lua_rawset(L, -3);

  return 1;
}

/**
 * Create a new process by duplicating the calling process.
 *
 * @function fork
 * @treturn number The PID of the child process is returned in the parent, and
 *   0 is returned in the child.
 * @error Error message.
 * @see fork(2)
 */
static int l_fork(lua_State *L)
{
  pid_t pid = fork();

  if (pid == -1)
  {
    int err = errno; // save errno because subsequent code might do something that changes it
    lua_pushnil(L);
    lua_pushstring(L, strerror(err));
    return 2;
  }
  lua_pushinteger(L, pid);
  return 1;
}

/**
 * Get the process ID of the calling process.
 *
 * @function getpid
 * @treturn number The process ID of the calling process.
 * @see getpid(2)
 */
static int l_getpid(lua_State *L)
{
  // getpid() never returns errors.
  pid_t pid = getpid();

  lua_pushinteger(L, pid);
  return 1;
}

/**
 * Get username of user running the calling process.
 *
 * @function getusername
 * @treturn string The username of the user running the calling process.
 * @error Error message.
 * @see getuid(2), getpwnam(3)
 */
static int l_getusername(lua_State *L)
{
  // getuid() never returns errors.
  uid_t uid = getuid();

  // Per specification: if one wants to check errno after calling getpwuid(), it must first be set to zero.
  errno = 0;

  struct passwd* passwd = getpwuid(uid);

  if(NULL == passwd)
  {
    int err = errno;  // save errno because subsequent code might do something that changes it
    lua_pushnil(L);
    lua_pushstring(L, strerror(err));
    return 2;
  }

  lua_pushstring(L, passwd->pw_name);
  return 1;
}

/**
 * Replace the current process image with a new process image.
 * This function only returns if an error occurred.
 *
 * @function execv
 *
 * @string path The file to be executed.
 * @tparam[opt] {string,...} argv Array with the arguments to provide to the new program.
 * @error Error message.
 * @see execv(3)
 * @see execve(2)
 */
static int l_execv(lua_State *L)
{
  const char  *path = luaL_checkstring(L, 1);
  size_t       argc = 2; // the program name must always be present + a NULL terminator
  char       **argv;
  unsigned int i;

  if (lua_istable(L, 2))
  {
    argc += lua_objlen(L, 2);
  }
  argv = malloc(argc * sizeof(char *));
  argv[0] = (char *)path;
  argv[argc - 1] = NULL;
  for (i = 1; i <= argc - 2; i++)
  {
    lua_rawgeti(L, 2, i);
    argv[i] = (char *)lua_tostring(L, -1);
    if (!argv[i])
    {
      free(argv);
      lua_pushnil(L);
      lua_pushstring(L, "argv must contain strings");
      return 2;
    }
  }
  if (execv(path, argv) == -1)
  {
    int err = errno;  // save errno because subsequent code might do something that changes it
    free(argv);
    lua_pushnil(L);
    lua_pushstring(L, strerror(err));
    return 2;
  }
  return 0; // never reached because execv() does not return on success.
}

/**
 * Duplicates the old file descriptor into the new file descriptor.
 * The new file descriptor is closed first if necessary.
 *
 * @function dup2
 * @tparam int oldfd The file descriptor to duplicate.
 * @tparam int newfd The file descriptor to duplicate to.
 * @treturn int The new file descriptor.
 * @error Error message.
 * @see dup2(2)
 */
static int l_dup2(lua_State *L)
{
  int oldfd = luaL_checkint(L, 1);
  int newfd = luaL_checkint(L, 2);

  if (dup2(oldfd, newfd) == -1)
  {
    int err = errno;  // save errno because subsequent code might do something that changes it
    lua_pushnil(L);
    lua_pushstring(L, strerror(err));
    return 2;
  }
  // We must return the new file descriptor, which sits on index 2.
  // Set the top of the stack to 2 to discard additional arguments and
  // then we can return.
  lua_settop(L, 2);
  return 1;
}

/**
 * Send signal to a process.
 *
 * @function kill
 * @tparam int pid The process ID of the process to send signal to.
 * @tparam int sig The signal to send to process: SIGTERM, SIGKILL or 0 to check if process exists.
 * @treturn number The return value of kill() or nil otherwise.
 * @error Error message.
 * @see kill(2)
 */
static int l_kill(lua_State *L)
{
  int pid = luaL_checkint(L, 1);
  int sig = luaL_checkint(L, 2);

  // Safeguard against accidental use:
  //   PID's 0 and smaller have special meaning - send to every process in process group etc, see kill(2) for more info.
  //     We will not support these unless there really is a need.
  //   PID 1 is the init process - it must not be killed.
  if(pid <= 1)
  {
    lua_pushnil(L);
    lua_pushstring(L, "Specfied PID must be greater than 1");
    return 2;
  }

  if(SIGKILL != sig &&
     SIGTERM != sig &&
     0       != sig)
  {
    lua_pushnil(L);
    lua_pushstring(L, "Invalid signal specified");
    return 2;
  }

  int ret = kill(pid, sig);

  if (-1 == ret)
  {
    int err = errno; // save errno because subsequent code might do something that changes it
    lua_pushnil(L);
    lua_pushstring(L, strerror(err));
    return 2;
  }

  lua_pushinteger(L, ret);
  return 1;
}

static int push_error(lua_State *L, const char *msg)
{
  lua_pushnil(L);
  lua_pushstring(L, msg);
  return 2;
}

/**
 * convert IP address to binary form
 *
 * @function inet_pton
 * @tparam int af The address family, either AF_INET or AF_INET6
 * @tparam string src The IP address string to convert
 * @treturn string the binary representation of the given address
 * @error error message
 * @see inet_pton(3)
 */
static int l_inet_pton(lua_State *L)
{
  int af = luaL_checkint(L, 1);
  const char *src = luaL_checkstring(L, 2);

  if( af == AF_INET ) {
    struct in_addr addr;
    if( inet_pton(af, src, &addr)==1) {
      lua_pushlstring(L, (char*)&addr, sizeof(addr));
      return 1;
    }
    else {
      return push_error(L, "not a valid IPv4 address");
    }
  }
  else if( af == AF_INET6 ) {
    struct in6_addr addr;
    if( inet_pton(af, src, &addr)==1) {
      lua_pushlstring(L, (char*)&addr, sizeof(addr));
      return 1;
    }
    else {
      return push_error(L, "not a valid IPv6 address");
    }
  }
  else {
    return push_error(L, "invalid address family");
  }
}

static const luaL_reg s_tch_posix[] =
{
  { "clock_gettime", l_clock_gettime },
  { "clock_elapsed", l_clock_elapsed },
  { "sysconf",       l_sysconf       },
  { "statvfs",       l_statvfs       },
  { "fork",          l_fork          },
  { "kill",          l_kill          },
  { "getpid",        l_getpid        },
  { "getusername",   l_getusername   },
  { "execv",         l_execv         },
  { "dup2",          l_dup2          },
  { "inet_pton",     l_inet_pton     },
  { "statvfs",       l_statvfs       },
  { NULL, NULL }
};

/**
 * Constants to be used in calls to functions of this module.
 * @field CLOCK_REALTIME Realtime clock ID for use in `clock_gettime` and `clock_elapsed`.
 * @field CLOCK_MONOTONIC Monotonic clock ID for use in `clock_gettime` and `clock_elapsed`.
 * @field ST_RDONLY Bit in the `f_flag` field of the table returned by `statvfs` indicating a read-only filesystem.
 * @field ST_NOSUID Bit in the `f_flag` field of the table returned by `statvfs` indicating set-user-ID and set-group-ID bits are ignored by `exec(3)`.
 * @field SIGKILL Using `kill`, send signal '9' to process. This is equivalent to shell command 'kill -9'.
 * @field SIGTERM Using `kill`, send signal '15' to process. This is equivalent to shell command `kill`, since SIGTERM is the default signal.
 * @field AF_INET IPv4 address family
 * @field Af_INET6 IPv6 address family
 * @table tch.posix
 */
static const ConstantEntry s_constants[] =
{
  CONSTANT(CLOCK_REALTIME),
  CONSTANT(CLOCK_MONOTONIC),
  CONSTANT(_SC_CLK_TCK),
  CONSTANT(ST_RDONLY),
  CONSTANT(ST_NOSUID),

  // signals for kill
  CONSTANT(SIGKILL),
  CONSTANT(SIGTERM),

  CONSTANT(AF_INET),
  CONSTANT(AF_INET6),
  { NULL, 0 }
};

int luaopen_tch_posix(lua_State *L)
{
  const ConstantEntry *c;

  lua_createtable(L, 0, ELEMS(s_tch_posix) + ELEMS(s_constants));
  luaL_register(L, NULL, s_tch_posix);
  for (c = s_constants; c->name; c++)
  {
    lua_pushstring(L, c->name);
    lua_pushinteger(L, c->value);
    lua_rawset(L, -3);
  }
  return 1;
}

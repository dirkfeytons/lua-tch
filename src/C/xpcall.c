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
 * A version of the standard `xpcall` function that supports arguments.
 *
 * In Lua 5.1 `xpcall` doesn't support calling a function with arguments. You
 * would have to use a closure, which isn't that efficient if you have to call
 * the function lots of times with varying arguments. They fixed this in Lua
 * 5.2 but since we don't have that we create a backport.
 * @module tch.xpcall
 * @usage
 * local xpcall = require("tch.xpcall")
 * local rc, result1, result2 = xpcall(some_func, debug.traceback, arg1, arg2)
 */

#include <lua.h>
#include <lauxlib.h>
#include "common.h"

// Implementation is pretty much a backport of the Lua 5.2 code.
static int l_xpcall(lua_State *L)
{
  int status;
  int n = lua_gettop(L);

  luaL_argcheck(L, n >= 2, 2, "value expected");
  lua_pushvalue(L, 1);  /* copy function... */
  lua_pushvalue(L, 2);  /* ...and error handler */
  lua_replace(L, 1);    /* put error handler in first position... */
  lua_replace(L, 2);    /* ...and function in second */
  status = lua_pcall(L, n - 2, LUA_MULTRET, 1);
  if (!lua_checkstack(L, 1))  /* no space for extra boolean? */
  {
    lua_settop(L, 0);  /* create space for return values */
    lua_pushboolean(L, 0);
    lua_pushliteral(L, "stack overflow");
    return 2;  /* return false, msg */
  }
  lua_pushboolean(L, status == 0); /* first result (status) */
  lua_replace(L, 1);  /* put first result in first slot */
  return lua_gettop(L);
}

int luaopen_tch_xpcall(lua_State *L)
{
  lua_pushcfunction(L, l_xpcall);
  return 1;
}

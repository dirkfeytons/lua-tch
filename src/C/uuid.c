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
 * Bindings to UUID functions and useful wrappers around them.
 * @module tch.uuid
 */

#include <lua.h>
#include <lauxlib.h>
#include <uuid/uuid.h>
#include "common.h"

/**
 * Create a new unique UUID value
 *
 * @function uuid_generate
 * @treturn string The generated uuid, 36 characters in length.
 * @see uuid_generate(3)
 */
static int l_uuid_generate(lua_State *L)
{
  #define LENGTH (36+1) // uuid in format 8-4-4-4-12, plus trailing zero. Do not mess with this length!

  uuid_t uuid;
  char out[LENGTH];

  uuid_generate(uuid);
  uuid_unparse(uuid, out);

  // uuid_unparse should yield zero-terminated 36-char string, but be safe.
  out[LENGTH-1] = '\0';

  lua_pushstring(L, out);
  return 1;
}

static const luaL_reg s_tch_uuid[] =
{
  { "uuid_generate", l_uuid_generate },
  { NULL, NULL }
};

int luaopen_tch_uuid(lua_State *L)
{
  lua_createtable(L, 0, ELEMS(s_tch_uuid));
  luaL_register(L, NULL, s_tch_uuid);
  return 1;
}

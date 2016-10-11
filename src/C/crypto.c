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
 * Bindings to crypto functions.
 * @module tch.crypto
 */

#include <stdio.h>
#include <lua.h>
#include <lauxlib.h>
#include <openssl/md5.h>
#include "common.h"

/**
 * Calculate the MD5 hash in hexadecimal notation of the given string.
 *
 * @function md5
 * @string s The string to calculate the hash of.
 * @treturn string The hexadecimal representation of the MD5 hash of
 *   the given string.
 * @raise Throws in case the given argument is not a string.
 */
static int l_crypto_md5(lua_State *L)
{
  unsigned char        digest[MD5_DIGEST_LENGTH];
  char                 digest_hex[(2*MD5_DIGEST_LENGTH) + 1];
  size_t               data_len;
  const unsigned char *data = (const unsigned char *)luaL_checklstring(L, 1, &data_len);
  int                  i;

  MD5(data, data_len, digest);
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    sprintf(&digest_hex[i*2], "%02x", digest[i]);
  lua_pushlstring(L, digest_hex, 2*MD5_DIGEST_LENGTH);
  return 1;
}

static const luaL_reg s_tch_crypto[] =
{
  { "md5", l_crypto_md5 },
  { NULL,  NULL }
};

int luaopen_tch_crypto(lua_State *L)
{
  lua_createtable(L, 0, ELEMS(s_tch_crypto));
  luaL_register(L, NULL, s_tch_crypto);
  return 1;
}

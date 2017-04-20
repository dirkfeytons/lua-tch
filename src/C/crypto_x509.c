/*
 * Copyright (c) 2017 Technicolor Delivery Technologies, SAS
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
 * Lua C module exposing X.509 certificates.
 *
 * @module tch.crypto.x509
 * @usage
 * Example code:
 *   local x509 = require("tch.crypto.x509")
 *   local cert = x509.new_from_string(string_data)
 *   local shash = cert:subject_hash()
 *   cert:free()
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "common.h"

#define CRYPTO_X509_MT "tch.crypto.x509"

// To check the user data object from the X509 module table
#define CHECK_OBJECT(idx)  (X509 **) luaL_checkudata(L, idx, CRYPTO_X509_MT)

// Max hash length is 32 bit(8 hexadecimal characters)
#define MAX_HASH_LENGTH 9

/**
 * Create a new X.509 certificate object from a string.
 * @function new_from_string
 * @tparam string certificate_data String data containing the certificate info in PEM format.
 * @treturn cert The newly created X.509 object from the given string.
 * @error Error message.
 */
static int l_x509_new_from_str(lua_State *L)
{
  size_t data_len;
  const char *pem = luaL_checklstring(L, 1, &data_len);

  X509 **udata = lua_newuserdata(L, sizeof(X509 *));

  BIO *bio = BIO_new_mem_buf((void *)pem, data_len);
  if (bio == NULL)
  {
    lua_pushnil(L);
    lua_pushliteral(L, "Allocation failed");
    return 2;
  }

  *udata = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if (*udata == NULL)
  {
    lua_pushnil(L);
    lua_pushliteral(L, "Read failed");
    return 2;
  }

  luaL_getmetatable(L, CRYPTO_X509_MT);
  lua_setmetatable(L, -2);

  return 1;
}

/**
 * X.509 methods.
 * @type cert
 */

/**
 * Subject hash from certificate.
 * Calculate the hash in hexadecimal notation of the subject of this certificate.
 * @function cert:subject_hash
 * @treturn string The hexadecimal representation of the hash of the subject.
 */
static int l_x509_subject_hash(lua_State *L)
{
  X509 **cert = CHECK_OBJECT(1);

  if (*cert)
  {
    char output_string[MAX_HASH_LENGTH];
    snprintf(output_string, sizeof(output_string), "%08lx", X509_subject_name_hash(*cert));
    lua_pushstring(L, output_string);
    return 1;
  }

  return 0;
}

/**
 * Free the X.509 certificate.
 * It's not an error to free an object more than once. Calling methods on a freed certificate will result in errors.
 * @function cert:free
 */
static int l_x509_free(lua_State *L)
{
  X509 **cert = CHECK_OBJECT(1);

  if (*cert)
  {
    X509_free(*cert);
    *cert = NULL;
  }

  return 0;
}

// Methods on a Crypto X.509 objects.
static const luaL_reg s_crypto_x509_methods[] = {
  { "__gc",		l_x509_free },
  { "free",		l_x509_free },
  { "subject_hash",	l_x509_subject_hash },
  { NULL,		NULL }
};

// Public functions for Crypto X.509 module.
static const luaL_reg s_crypto_x509_func[] = {
  { "new_from_string",	l_x509_new_from_str },
  { NULL,		NULL }
};

int luaopen_tch_crypto_x509(lua_State *L)
{
  // construct metatable with the methods for a crypto X509 object
  // and that is at the same time used as userdata tag
  luaL_newmetatable(L, CRYPTO_X509_MT);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");

  luaL_register(L, NULL, s_crypto_x509_methods);

  // create our module; note that we don't register a global variable!
  lua_createtable(L, 0, ELEMS(s_crypto_x509_func));
  luaL_register(L, NULL, s_crypto_x509_func);

  return 1;
}


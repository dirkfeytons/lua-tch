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
 * Lua C module exposing digest functions.
 *
 * @module tch.crypto.digest
 * @usage
 *   local digest = require("tch.crypto.digest")
 *   local hmac = digest.hmac(digest.SHA256, "key", "data")
 *   local sig_OK = digest.verify(digest.SHA256, "pubkey.pem",
 *                                "signature.sig", "checksums")
 */

#include <stdio.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "common.h"

#define CRYPTO_DIGEST_MT "tch.crypto.digest"

//Enum values for supported hashing algorithms
typedef enum
{
  TCH_DIGEST_SHA256,
  TCH_DIGEST_SHA1,
  TCH_DIGEST_MD5
} digest_t;

// Returns the output of corresponding EVP method for the given digest algorithm
static const EVP_MD *digest_enum_to_EVP_MD(digest_t alg)
{
  switch (alg)
  {
   case TCH_DIGEST_SHA256:
     return EVP_sha256();

   case TCH_DIGEST_SHA1:
     return EVP_sha1();

   case TCH_DIGEST_MD5:
     return EVP_md5();

   default:
     return NULL;
  }
}

/**
 * Calculate a message authentication code (MAC) for the given data using a keyed hash function.
 * @function hmac
 * @int digest One of the `TCH_DIGEST_*` constants indicating the digest (hash) algorithm to use.
 * @string key The key to use.
 * @string data The data over which to calculate the MAC.
 * @treturn string The calculated MAC in hexstring format.
 * @error Error message.
 */
static int hmac(lua_State *L)
{
  int alg = luaL_checkint(L, 1);

  const EVP_MD *md = digest_enum_to_EVP_MD(alg);
  if (!md)
    return luaL_error(L, "Invalid digest algorithm %d", alg);

  size_t key_len, data_len;
  const char *key = luaL_checklstring(L, 2, &key_len);
  const char *data = luaL_checklstring(L, 3, &data_len);

  unsigned char output_string[EVP_MAX_MD_SIZE];
  unsigned char *hmac_status;
  unsigned int output_len;

  hmac_status = HMAC(md, key, key_len, (unsigned char *)data, data_len, output_string, &output_len);

  if (hmac_status != NULL)
  {
    char hexoutput_string[(EVP_MAX_MD_SIZE * 2) + 1];
    //convert string (output_string) to hexadecimal (hexoutput_string)
    bytes_to_hexstring(output_string, output_len, hexoutput_string);

    lua_pushlstring(L, hexoutput_string, (2*output_len));
    return 1;
  }

  lua_pushnil(L);
  lua_pushliteral(L, "HMAC failed");
  return 2;
}

/**
 * Verify the signature for the given algorithm, public key and
 * data using the given digest algorithm.
 * @function verify
 * @int digest One of the `TCH_DIGEST_*` constants indicating the digest (hash) algorithm to use.
 * @string pubkey_file Location of the file containing the public key in PEM format.
 * @string signature_file Location of the file containing the signature.
 * @string data_file Location of the file containing the data to verify.
 * @treturn boolean True if verification succeeded.
 * @error Error message.
 */
static int verify(lua_State *L)
{
  const EVP_MD *md = NULL;
  digest_t digest = luaL_checkint(L, 1);
  const char *pubkeyfile = luaL_checkstring(L, 2);
  const char *sigfile = luaL_checkstring(L, 3);
  const char *datafile = luaL_checkstring(L, 4);
  const char *errmsg = NULL;
  EVP_MD_CTX *mdctx = NULL;
  FILE *pubkey_fp = NULL;
  EVP_PKEY *pubkey = NULL;
  int sig_fd = -1;
  struct stat sigfile_stat;
  unsigned char *sig_data = NULL;
  int data_fd = -1;
  int verification = 0;

  ERR_clear_error(); // make sure OpenSSL's error stack is empty
  md = digest_enum_to_EVP_MD(digest);
  if (!md)
    return luaL_error(L, "Invalid digest algorithm %d", digest);
  // read the public key file
  pubkey_fp = fopen(pubkeyfile, "r");
  if (!pubkey_fp)
  {
    errmsg = "Failed to open the public key file";
    goto error;
  }
  pubkey = PEM_read_PUBKEY(pubkey_fp, NULL, NULL, NULL);
  if (!pubkey)
  {
    fclose(pubkey_fp);
    errmsg = "Failed to read public key";
    goto error;
  }
  fclose(pubkey_fp);
  // read the signature file
  sig_fd = open(sigfile, O_RDONLY | O_CLOEXEC);
  if (sig_fd == -1)
  {
    errmsg = "Failed to open signature file";
    goto error;
  }
  if (fstat(sig_fd, &sigfile_stat) == -1)
  {
    errmsg = "Failed to stat signature file";
    goto error;
  }
  sig_data = malloc(sigfile_stat.st_size);
  if (!sig_data)
  {
    errmsg = "Failed to allocate memory for signature data";
    goto error;
  }
  if (read(sig_fd, sig_data, sigfile_stat.st_size) != sigfile_stat.st_size)
  {
    errmsg = "Failed to read signature data";
    goto error;
  }
  // open data file
  data_fd = open(datafile, O_RDONLY | O_CLOEXEC);
  if (data_fd == -1)
  {
    errmsg = "Failed to open data file";
    goto error;
  }
  // start verification
  mdctx = EVP_MD_CTX_create();
  if (!mdctx)
  {
    errmsg = "Failed to create a digest context";
    goto error;
  }
  if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pubkey) != 1)
  {
    errmsg = "Failed to create verification context";
    goto error;
  }
  // read data and feed it to verification context
  do
  {
    char buffer[256];
    ssize_t data_read = read(data_fd, buffer, sizeof(buffer));
    if (data_read <= 0)
      break;
    if (EVP_DigestVerifyUpdate(mdctx, buffer, data_read) != 1)
    {
      errmsg = "Failed to update verification context";
      goto error;
    }
  } while(1);
  // finalize the verification; 1 means success and any other value indicates failure
  verification = EVP_DigestVerifyFinal(mdctx, sig_data, sigfile_stat.st_size);
  if (verification != 1)
    errmsg = ERR_error_string(ERR_get_error(), NULL);

error:
  if (mdctx)
    EVP_MD_CTX_destroy(mdctx);
  if (data_fd != -1)
    close(data_fd);
  free(sig_data);
  if (pubkey)
    EVP_PKEY_free(pubkey);
  if (errmsg)
  {
    unsigned long err = ERR_get_error();
    if (err != 0)
      errmsg = ERR_error_string(err, NULL);
    ERR_clear_error();  // be nice and make sure OpenSSL's error stack is empty
    lua_pushnil(L);
    lua_pushstring(L, errmsg);
    return 2;
  }
  lua_pushboolean(L, verification);
  return 1;
}

/**
 * Supported digest (hash) algorithms.
 * @field SHA256 The SHA256 hash algorithm.
 * @field SHA1 The SHA1 hash algorithm.
 * @field MD5 The MD5 hash algorithm.
 * @table tch.crypto.digest
 */
static const ConstantEntry s_constants[] =
{
  { "SHA256", TCH_DIGEST_SHA256 },
  { "SHA1",   TCH_DIGEST_SHA1 },
  { "MD5",    TCH_DIGEST_MD5 },
  { NULL,     0 }
};

// Public functions for crypto hmac sha256 module
static const luaL_reg s_crypto_digest_func[] =
{
  { "hmac",   hmac },
  { "verify", verify },
  { NULL,     NULL }
};

int luaopen_tch_crypto_digest(lua_State *L)
{
  const ConstantEntry *c;

  // construct metatable with the methods for a crypto digest object
  // and that is at the same time used as userdata tag
  luaL_newmetatable(L, CRYPTO_DIGEST_MT);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");

  // create our module; note that we don't register a global variable!
  lua_createtable(L, 0, ELEMS(s_crypto_digest_func) + ELEMS(s_constants));
  luaL_register(L, NULL, s_crypto_digest_func);
  for (c = s_constants; c->name; c++)
  {
    lua_pushstring(L, c->name);
    lua_pushinteger(L, c->value);
    lua_rawset(L, -3);
  }

  return 1;
}

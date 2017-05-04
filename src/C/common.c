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

#include <stdio.h>
#include "common.h"

// Converts the given input to hexadecimal string and stores it in output
void bytes_to_hexstring(const unsigned char * restrict input, size_t input_len, char * restrict output)
{
  size_t index;
  static const char hexchars[] = "0123456789abcdef";
  for (index = 0; index < input_len; index++)
  {
    output[index * 2] = hexchars[(input[index] >> 4) & 0xF];
    output[(index * 2) + 1] = hexchars[(input[index]) & 0xF];
  }
  output[index * 2] = '\0';
}

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

#ifndef LUA_TCH_COMMON_H
#define LUA_TCH_COMMON_H

#ifndef HIDDEN
#define HIDDEN __attribute__((visibility("hidden")))
#endif

/*
 * Convert the given bytes to a hexadecimal string.
 * @param input The bytes to convert. This does not need to be null terminated.
 * @param input_len The number of bytes to convert.
 * @param output Buffer to which the output will be written.
 * The output will be null terminated.
 * The caller has to ensure the buffer is at least (2*input_len)+1 in size.
 */
void bytes_to_hexstring(const unsigned char * restrict input, size_t input_len, char * restrict output) HIDDEN;

// For arrays with a sentinel (!!) returns the number of elements,
// excluding the sentinel.
#define ELEMS(arr)   ((sizeof(arr)/sizeof(arr[0]))-1)
#define CONSTANT(c)  { #c, c }

typedef struct
{
  const char *name;
  int         value;
} ConstantEntry;

#endif

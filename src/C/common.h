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

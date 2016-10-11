--[[
Copyright (c) 2016 Technicolor Delivery Technologies, SAS

The source code form of this lua-tch component is subject
to the terms of the Clear BSD license.

You can redistribute it and/or modify it under the terms of the
Clear BSD License (http://directory.fsf.org/wiki/License:ClearBSD)

See LICENSE file for more details.
]]

---
-- A simple profiling module.
--
-- Every time `start()` is called it will record a timestamp on a stack.
-- Every time `stop()` is called it will calculate the elapsed time with
-- the timestamp currently on the top of the stack. This info is used
-- to build a call tree with timings. Note that this means you have
-- to use the functions in a balanced way.
--
-- **This is an internal development module and normally not installed
-- on target.**
-- @module tch.profiling
-- @usage
-- local profiling = require("tch.profiling")
-- local function some_time_consuming_function()
--   profiling.start("some_time_consuming_function")
--   calculations here
--   profiling.stop("some_time_consuming_function")
-- end
-- local function foo()
--   profiling.start("foo")
--   some_time_consuming_function()
--   some_other_time_consuming_function()
--   profiling.stop("foo")
--   profiling.dump("/tmp/profile.log")
-- end

local posix = require("tch.posix")
local CLOCK_MONOTONIC = posix.CLOCK_MONOTONIC
local clock_gettime = posix.clock_gettime
local clock_elapsed = posix.clock_elapsed
local format = string.format
local rawset = rawset

local timingtable = {}
local profile_log = {}
local indent = 1

---
-- Record a starting timestamp with the given name.
-- You can nest calls to this function. The recorded timestamps
-- are organized in a stack.
-- @string name A description for the timestamp.
-- @see stop
-- @see dump
local function start(name)
  profile_log[#profile_log + 1] = { name = name, indent = indent }
  timingtable[indent] =  { clock_gettime(CLOCK_MONOTONIC) }
  indent = indent + 1
end

---
-- Take a new timestamp, calculate the elapsed time since the
-- timestamp at the top of the stack and record it with the given name.
-- @string name A description for the elapsed time. It doesn't have to
--   be the same name as in the `start()` call but it might help
--   help to interpret the results.
-- @see start
-- @see dump
local function stop(name)
  indent = indent - 1
  local ts = timingtable[indent]
  profile_log[#profile_log + 1] = { time = clock_elapsed(CLOCK_MONOTONIC, ts[1], ts[2]), name = name, indent = indent }
end

-- prefix string cache
local prefixes = setmetatable({}, {
  __index = function(t, i)
    local prefix = ("-"):rep(i)
    rawset(t, i, prefix)
    return prefix
  end
})

---
-- Write the collected profiling data to the given file.
--
-- @string filename The full path to the file to write the data to.
-- @bool append Whether to append to the given filename or overwrite it.
-- @see start
-- @see stop
local function dump(filename, append)
  local flag = "w"
  if append then
    flag = "a"
  end
  local f = io.open(filename, flag)
  for _, entry in ipairs(profile_log) do
    local prefix = prefixes[entry.indent]
    if entry.time then
      f:write(format("<%s %s %.2f msecs\n", prefix, entry.name, entry.time/1000))
    else
      f:write(format("%s> %s\n", prefix, entry.name))
    end
  end
  f:close()
  timingtable = {}
  profile_log = {}
  indent = 1
end

--- @export
return {
  dump = dump,
  start = start,
  stop = stop
}

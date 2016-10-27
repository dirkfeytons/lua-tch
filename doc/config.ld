title = "Technicolor Lua Modules Documentation"
project = "lua-tch"
description = "Various useful Lua snippets and bindings to C functionality."
boilerplate = true
sort = true
no_space_before_args = true
backtick_references = true
not_luadoc = true
format = "markdown"

local upat = "http://linux.die.net/man/%s/%s"
custom_see_handler('^([%w_]+)%((%d)%)$', function(name, section)
 local url = upat:format(section, name)
 local name = name .. '(' .. section .. ')'
 return name, url
end)

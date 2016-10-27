# lua-tch

A collection of Lua modules with useful utility functions and bindings to C
functions and libraries.

Documentation of the API can be found on https://dirkfeytons.github.io/lua-tch/
It's generated with [LDoc](https://github.com/stevedonovan/ldoc). The config
used to generate the documentation can be found in `./doc/config.ld`.
Generating the documentation is as simple as `ldoc -c ./doc/config.ld src/`
from the root of the repository. The generated documentation can then be found
in `./doc`.

This code was originally developed in [Technicolor](http://www.technicolor.com/),
hence the `-tch` in the name.

## Dependencies

`lua-tch` uses or binds functionality from the following libraries:

- [Lua](http://www.lua.org)
- [OpenSSL](https://www.openssl.org/)
- [libubox](https://git.lede-project.org/?p=project/libubox.git)
- A netlink library such as libnl-tiny from [OpenWrt](https://github.com/openwrt/openwrt/tree/master/package/libs/libnl-tiny)/
[LEDE](https://git.lede-project.org/?p=source.git;a=tree;f=package/libs/libnl-tiny)
- [libuuid](https://www.kernel.org/pub/linux/utils/util-linux/)


## License

`lua-tch` uses the 2-clause ClearBSD license.

For detailse see the `LICENSE` file.


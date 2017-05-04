cmake_minimum_required(VERSION 2.8)

project(lua-tch C)
OPTION(HOST "Build for host machine" OFF)


set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

find_package(LIBLUA REQUIRED)
find_package(LIBUUID REQUIRED)
find_package(OpenSSL REQUIRED)

add_definitions(-Os -Wall -Wextra -Werror -std=gnu99 -D_GNU_SOURCE)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} --coverage")

set(SOURCES
  src/C/crypto.c
  src/C/crypto_x509.c
  src/C/posix.c
  src/C/uuid.c
  src/C/xpcall.c
  src/C/socket_unix.c
  src/C/socket_evloop.c
  src/C/timer_fd.c
)
set(INCLUDES
  ${LIBLUA_INCLUDE_DIR}
  ${LIBUUID_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR}
)
set(LIBS rt ${LIBUUID_LIBRARIES} ${OPENSSL_LIBRARIES})

# Shouldn't link against LIBLUA_LIBRARIES, it's not needed and can cause
# issues

IF(NOT HOST)
  find_package(UBUS REQUIRED)
  find_package(LIBNL-TINY REQUIRED)

  set(SOURCES ${SOURCES} src/C/netlink.c)
  set(LIBS ${LIBS} ${LIBNL-TINY_LIBRARIES} ${UBOX_LIBRARY})
  set(INCLUDES ${INCLUDES} ${UBOX_INCLUDE_DIR} ${LIBNL-TINY_INCLUDE_DIR})
ENDIF(NOT HOST)

add_library(lua-tch MODULE ${SOURCES})
include_directories(${INCLUDES})
target_link_libraries(lua-tch ${LIBS})

set_target_properties(lua-tch PROPERTIES
        PREFIX ""
        OUTPUT_NAME tch
        LINK_FLAGS_DEBUG --coverage
        LINK_FLAGS "-Wl,--as-needed")

install(TARGETS lua-tch
        LIBRARY DESTINATION lib/lua)
install(FILES src/Lua/tableprint.lua src/Lua/inet.lua src/Lua/logger.lua
        DESTINATION lib/lua/tch)

IF (LIBUUID_INCLUDE_DIR)
  # Already in cache, be silent
  SET(LIBUUID_FIND_QUIETLY TRUE)
ENDIF (LIBUUID_INCLUDE_DIR)

FIND_PATH(LIBUUID_INCLUDE_DIR uuid/uuid.h)

SET(LIBUUID_NAMES uuid)
FIND_LIBRARY(LIBUUID_LIBRARY NAMES ${LIBUUID_NAMES})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBUUID DEFAULT_MSG LIBUUID_LIBRARY LIBUUID_INCLUDE_DIR)

IF(LIBUUID_FOUND)
  SET( LIBUUID_LIBRARIES ${LIBUUID_LIBRARY} )
ELSE(LIBUUID_FOUND)
  SET( LIBUUID_LIBRARIES )
ENDIF(LIBUUID_FOUND)

MARK_AS_ADVANCED( LIBUUID_LIBRARIES LIBUUID_INCLUDE_DIR )

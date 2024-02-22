cmake_minimum_required(VERSION 3.7.0 FATAL_ERROR)

find_package(IRODS 4.3.1 EXACT REQUIRED)
set(IRODS_PLUGIN_REVISION "0")
set(IRODS_PLUGIN_VERSION "${IRODS_VERSION}.${IRODS_PLUGIN_REVISION}")

set(IRODS_PACKAGE_REVISION "0")

include(IrodsCXXCompiler)
set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
include(IrodsRunpathDefaults)

project(irods_auth_plugin_pam_interactive
  VERSION "${IRODS_PLUGIN_VERSION}"
  LANGUAGES CXX
)

include(${IRODS_TARGETS_PATH})

include(GNUInstallDirs)
include(UseLibCXX)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(nlohmann_json "3.6.1" REQUIRED)

# pam interactive
if (NOT PAM_LIBRARY)
  find_library(PAM_LIBRARY pam)
  if (PAM_LIBRARY)
    message(STATUS "Found pam: ${PAM_LIBRARY}")
  else()
    message(FATAL_ERROR "pam library not found")
  endif()
endif()

# Testing executable
add_executable(
  pam_handshake_auth_check
  "${CMAKE_CURRENT_SOURCE_DIR}/src/auth_check_wrapper.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/auth_check_main.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pam_conversation.cpp"
)
target_link_libraries(
  pam_handshake_auth_check
  PRIVATE
  "${PAM_LIBRARY}"
)
install(
  TARGETS
  pam_handshake_auth_check
  RUNTIME
  DESTINATION "${IRODS_PLUGINS_DIRECTORY}/auth"
)

set(plugin_target_part "irods_auth_plugin-pam_interactive")

# Client-side plugin
add_library(
  "${plugin_target_part}_client"
  MODULE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pam_interactive.cpp"
)
target_link_libraries(
  "${plugin_target_part}_client"
  PRIVATE
  irods_common
  irods_plugin_dependencies
  irods_client
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
  nlohmann_json::nlohmann_json
  OpenSSL::Crypto
  ${CMAKE_DL_LIBS}
)
target_include_directories(
  "${plugin_target_part}_client"
  PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/server/api/include>"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
  "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
)
target_compile_definitions(
  "${plugin_target_part}_client"
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)
install(
  TARGETS
  "${plugin_target_part}_client"
  LIBRARY
  DESTINATION "${IRODS_PLUGINS_DIRECTORY}/auth"
)

# Server-side plugin
add_library(
  "${plugin_target_part}_server"
  MODULE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pam_interactive.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/handshake_session.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/auth_check_wrapper.cpp"
)
target_link_libraries(
  "${plugin_target_part}_server"
  PRIVATE
  irods_common
  irods_plugin_dependencies
  irods_server
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
  nlohmann_json::nlohmann_json
  OpenSSL::Crypto
  ${CMAKE_DL_LIBS}
)
target_include_directories(
  "${plugin_target_part}_server"
  PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/server/api/include>"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
  "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
)
target_compile_definitions(
  "${plugin_target_part}_server"
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  RODS_SERVER
  ENABLE_RE
  IRODS_ENABLE_SYSLOG
)
install(
  TARGETS
  "${plugin_target_part}_server"
  LIBRARY
  DESTINATION "${IRODS_PLUGINS_DIRECTORY}/auth"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_RUNTIME_NAME}
)

set(PLUGIN_PACKAGE_NAME irods-auth-plugin-pam-interactive)

include(IrodsCPackCommon)

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods/test")

set(CPACK_PACKAGE_VERSION ${IRODS_PLUGIN_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
#set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packaging/postinst;")
set(CPACK_DEBIAN_PACKAGE_BREAKS ${PLUGIN_PACKAGE_NAME})
set(CPACK_DEBIAN_PACKAGE_REPLACES ${PLUGIN_PACKAGE_NAME})
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
set(CPACK_RPM_PACKAGE_OBSOLETES ${PLUGIN_PACKAGE_NAME})
#set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/postinst")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

set(CPACK_DEBIAN_PACKAGE_NAME ${PLUGIN_PACKAGE_NAME})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server (= ${IRODS_VERSION}), irods-runtime (= ${IRODS_VERSION}), libc6, libpam0g")

set(CPACK_RPM_PACKAGE_NAME ${PLUGIN_PACKAGE_NAME})
set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}, pam")

if (NOT CPACK_GENERATOR)
  set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
  message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)

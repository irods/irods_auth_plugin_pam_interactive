cmake_minimum_required(VERSION 3.12.0 FATAL_ERROR)
find_package(IRODS REQUIRED)

set(IRODS_PLUGIN_REVISION "0")
set(IRODS_PLUGIN_VERSION "${IRODS_VERSION}.${IRODS_PLUGIN_REVISION}")
set(IRODS_PACKAGE_REVISION "1")

set(CMAKE_C_COMPILER  ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang)
set(CMAKE_CXX_COMPILER  ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)
set(CMAKE_EXE_LINKER_FLAGS_INIT "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")

include_directories(
  ${IRODS_EXTERNALS_FULLPATH_CLANG}/include/c++/v1
)

include(IrodsExternals)
include(IrodsCXXCompiler)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(IRODS_CXX_STANDARD "${CMAKE_CXX_STANDARD}")

set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")

project(irods_auth_interactive_pam
  VERSION "${IRODS_PLUGIN_VERSION}"
  LANGUAGES CXX
)

include(UseLibCXX)


# include(CheckCCompilerFlag)
# include(CheckCXXCompilerFlag)
# add_compile_options(-std=c++20)
add_link_options(-lpthread)
add_link_options(-lc++abi)

if (NOT DEFINED THREADS_PREFER_PTHREAD_FLAG)
  set(THREADS_PREFER_PTHREAD_FLAG TRUE)
endif()
find_package(Threads REQUIRED)

find_package(nlohmann_json)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

# pam interactive
if (NOT PAM_LIBRARY)
  find_library(PAM_LIBRARY pam)
  if (PAM_LIBRARY)
    message(STATUS "Found pam: ${PAM_LIBRARY}")
  else()
    message(FATAL_ERROR "pam library not found")
  endif()
endif()

add_executable(
  pam_handshake_auth_check
  src/auth_check_wrapper.cpp
  src/auth_check_main.cpp
  src/pam_conversation.cpp
)

target_link_libraries(
   pam_handshake_auth_check
   PRIVATE
   ${PAM_LIBRARY}
   ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++.so.1
   ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++abi.so.1
)


add_library(
  irods_auth_plugin-pam_interactive_client
  MODULE
  src/pam_interactive.cpp
)

target_link_libraries(
  irods_auth_plugin-pam_interactive_client
  PRIVATE
  irods_common
  irods_plugin_dependencies
  irods_client
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
   ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++.so.1
  nlohmann_json::nlohmann_json
  OpenSSL::Crypto
  ${CMAKE_DL_LIBS}
)

target_include_directories(
  irods_auth_plugin-pam_interactive_client
  PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/server/api/include>"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
  "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
)

target_compile_definitions(
  irods_auth_plugin-pam_interactive_client
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)

add_library(
  irods_auth_plugin-pam_interactive_server
  MODULE
  src/pam_interactive.cpp
  src/handshake_session.cpp
  src/auth_check_wrapper.cpp
)

target_link_libraries(
  irods_auth_plugin-pam_interactive_server
  PRIVATE
  irods_common
  irods_plugin_dependencies
  irods_server
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
   ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib/libc++.so.1
  nlohmann_json::nlohmann_json
  OpenSSL::Crypto
  ${CMAKE_DL_LIBS}
)

target_include_directories(
  irods_auth_plugin-pam_interactive_server
  PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/server/api/include>"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
  "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
)

target_compile_definitions(
  irods_auth_plugin-pam_interactive_server
  PRIVATE
  RODS_SERVER
  ENABLE_RE
  IRODS_ENABLE_SYSLOG
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)

install(TARGETS irods_auth_plugin-pam_interactive_client
        LIBRARY
        DESTINATION "/usr/lib/irods/plugins/auth/"
        COMPONENT client
)

install(TARGETS pam_handshake_auth_check
        RUNTIME
        DESTINATION "/usr/lib/irods/plugins/auth"
        COMPONENT server
)

install(TARGETS irods_auth_plugin-pam_interactive_server
        LIBRARY
        DESTINATION "/usr/lib/irods/plugins/auth/"
        COMPONENT server
)

include(IrodsCPackPlatform)
set(CPACK_PACKAGE_FILE_NAME "irods-auth-interactive-pam")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)

set(CPACK_RPM_PACKAGE_NAME "irods-auth-interactive-pam-server" COMPONENT server)
set(CPACK_RPM_PACKAGE_NAME "irods-auth-interactive-pam-client" COMPONENT client)
set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime = ${IRODS_VERSION}, curl-devel" )

# set(CPACK_DEBIAN_PACKAGE_NAME "irods-auth-interactive-pam-server" COMPONENT server)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING},irods-runtime, libcurl4-gnutls-dev")

# set(CPACK_DEBIAN_PACKAGE_NAME "irods-auth-interactive-pam-client" COMPONENT client)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Stefan Wolfsheimer")

include(CPack)

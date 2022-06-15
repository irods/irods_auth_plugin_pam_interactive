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


set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")

project(irods_resource_plugin-s3
  VERSION "${IRODS_PLUGIN_VERSION}"
  LANGUAGES CXX
)

# include(CheckCCompilerFlag)
# include(CheckCXXCompilerFlag)
add_compile_options(-std=c++20)
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
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)

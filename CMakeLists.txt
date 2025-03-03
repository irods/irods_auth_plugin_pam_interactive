cmake_minimum_required(VERSION 3.7.0 FATAL_ERROR)

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

set(IRODS_MINIMUM_VERSION "4.3.1")
find_package(IRODS "${IRODS_MINIMUM_VERSION}" REQUIRED)
set(IRODS_PLUGIN_VERSION "0.1.1")

set(IRODS_PACKAGE_REVISION "0")

include(IrodsCXXCompiler)
set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_EXE_LINKER_FLAGS_INIT "-rdynamic -Wl,--export-dynamic -Wl,--enable-new-dtags -Wl,--as-needed")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
include(IrodsRunpathDefaults)

project(irods_auth_plugin_pam_interactive
	VERSION "${IRODS_PLUGIN_VERSION}"
	LANGUAGES CXX
)

set(plugin_target_part "irods_auth_plugin-pam_interactive")
string(REPLACE "_" "-" project_component_part "${plugin_target_part}")

include("${IRODS_TARGETS_PATH}")

include(GNUInstallDirs)
include(UseLibCXX)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(nlohmann_json "3.6.1" REQUIRED)
find_package(fmt "8.1.1"
	HINTS "${IRODS_EXTERNALS_FULLPATH_FMT}")
find_package(spdlog "1.9.2"
	HINTS "${IRODS_EXTERNALS_FULLPATH_SPDLOG}")
find_package(PAM REQUIRED)

add_subdirectory(common)
add_subdirectory(auth_check_wrapper)
add_subdirectory(pam_handshake_auth_check)
add_subdirectory(plugin)

# Install the test file(s) alongside the server package.
install(
	FILES
	${CMAKE_SOURCE_DIR}/packaging/test_irods_auth_plugin_pam_interactive.py
	DESTINATION ${IRODS_HOME_DIRECTORY}/scripts/irods/test
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	COMPONENT
	"${project_component_part}-server"
)

set(PLUGIN_PACKAGE_NAME "irods-auth-plugin-pam-interactive")

include(IrodsCPackCommon)

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods/test")

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_PLUGINS_DIRECTORY}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_PLUGINS_DIRECTORY}/auth")

set(CPACK_PACKAGE_VERSION ${IRODS_PLUGIN_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")

set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

string(TOUPPER "${project_component_part}-client" irods_plugin_package_client_component)
string(TOUPPER "${project_component_part}-server" irods_plugin_package_server_component)

set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-client")
set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_DEPENDS "irods-runtime (= ${IRODS_VERSION}), libc6")
set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_BREAKS "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~), irods-auth-interactive-pam (<< 4.90.0.0-1~)")
set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_REPLACES "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~), irods-auth-interactive-pam (<< 4.90.0.0-1~)")

set(CPACK_RPM_${irods_plugin_package_client_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-client")
set(CPACK_RPM_${irods_plugin_package_client_component}_PACKAGE_REQUIRES "irods-runtime = ${IRODS_VERSION}")

set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-server")
set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_DEPENDS "irods-server (= ${IRODS_VERSION}), ${CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_NAME} (= ${CPACK_PACKAGE_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}), libpam0g")
set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_BREAKS "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~), irods-auth-interactive-pam (<< 4.90.0.0-1~)")
set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_REPLACES "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~), irods-auth-interactive-pam (<< 4.90.0.0-1~)")
set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packaging/postinst;")

set(CPACK_RPM_${irods_plugin_package_server_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-server")
set(CPACK_RPM_${irods_plugin_package_server_component}_PACKAGE_REQUIRES "irods-server = ${IRODS_VERSION}, ${CPACK_RPM_${irods_plugin_package_client_component}_PACKAGE_NAME} = ${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}, pam")
set(CPACK_RPM_${irods_plugin_package_server_component}_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/postinst")

if (NOT CPACK_GENERATOR)
	set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
	message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)

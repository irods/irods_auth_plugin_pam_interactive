include(ObjectTargetHelpers)

foreach(plugin_variant IN ITEMS client server)
	add_library(
		"${plugin_target_part}_${plugin_variant}"
		MODULE
		"${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
	)
	target_link_libraries(
		"${plugin_target_part}_${plugin_variant}"
		PRIVATE
		irods_pam_interactive_common
		irods_common
		irods_plugin_dependencies
		"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
		"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
		nlohmann_json::nlohmann_json
		OpenSSL::Crypto
		fmt::fmt
	)
	target_include_directories(
		"${plugin_target_part}_${plugin_variant}"
		PRIVATE
		"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
		"${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
	)
	target_compile_definitions(
		"${plugin_target_part}_${plugin_variant}"
		PRIVATE
		${IRODS_COMPILE_DEFINITIONS_PRIVATE}
	)

	install(
		TARGETS
		"${plugin_target_part}_${plugin_variant}"
		LIBRARY
		DESTINATION "${IRODS_AUTHENTICATION_PLUGINS_DIRECTORY}"
		COMPONENT "${project_component_part}-${plugin_variant}"
	)
endforeach()

target_link_libraries(
	"${plugin_target_part}_client"
	PRIVATE
	irods_client
)

target_sources(
	"${plugin_target_part}_server"
	PRIVATE
	"${CMAKE_CURRENT_SOURCE_DIR}/src/handshake_session.cpp"
)
target_link_objects(
	"${plugin_target_part}_server"
	PRIVATE
	irods_pam_auth_check_wrapper_obj
)
target_link_libraries(
	"${plugin_target_part}_server"
	PRIVATE
	PAM::pam
	irods_server
	${CMAKE_DL_LIBS}
)
if (IRODS_VERSION VERSION_LESS "4.3.2")
	target_link_libraries(
		"${plugin_target_part}_server"
		PRIVATE
		spdlog::spdlog_header_only
	)
else()
	target_link_libraries(
		"${plugin_target_part}_server"
		PRIVATE
		spdlog::spdlog
	)
endif()
target_compile_definitions(
	"${plugin_target_part}_server"
	PRIVATE
	RODS_SERVER
	ENABLE_RE
	IRODS_ENABLE_SYSLOG
)

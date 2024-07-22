include(ObjectTargetHelpers)

add_executable(
	pam_handshake_auth_check
	"${CMAKE_CURRENT_SOURCE_DIR}/src/auth_check_main.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/src/pam_conversation.cpp"
)
target_link_objects(
	pam_handshake_auth_check
	PRIVATE
	irods_pam_auth_check_wrapper_obj
)
target_link_libraries(
	pam_handshake_auth_check
	PRIVATE
	PAM::pam
)
target_include_directories(
	pam_handshake_auth_check
	PRIVATE
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)

install(
	TARGETS
	pam_handshake_auth_check
	RUNTIME
	DESTINATION "${IRODS_PLUGINS_DIRECTORY}/auth"
	COMPONENT "${project_component_part}-server"
	PERMISSIONS SETUID OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

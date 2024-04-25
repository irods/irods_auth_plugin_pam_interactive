add_library(
	irods_pam_auth_check_wrapper_obj
	OBJECT
	"${CMAKE_CURRENT_SOURCE_DIR}/src/auth_check_wrapper.cpp"
)
target_link_libraries(
	irods_pam_auth_check_wrapper_obj
	PUBLIC
	irods_pam_interactive_common
	PAM::pam
)
target_include_directories(
	irods_pam_auth_check_wrapper_obj
	PUBLIC
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)

set_target_properties(irods_pam_auth_check_wrapper_obj PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
set_target_properties(irods_pam_auth_check_wrapper_obj PROPERTIES EXCLUDE_FROM_ALL TRUE)

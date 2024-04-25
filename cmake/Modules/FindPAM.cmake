#[=======================================================================[.rst:
FindPAM
-----------

Finds PAM.

IMPORTED Targets
^^^^^^^^^^^^^^^^

The following :prop_tgt:`IMPORTED` targets may be defined:

``PAM::pam``
  Main PAM library.

Result variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``PAM_FOUND``
  true if PAM headers and library were found
``PAM_LIBRARY``
  PAM library to be linked
``PAM_INCLUDE_DIR``
  the directory containing PAM headers

TODO (irods/irods#6247)
^^^^^^^^^^^^^^^^^^^^^^^

* pam_misc
* pamc
* Components
* Version matching
* pkgconfig?

#]=======================================================================]

cmake_policy(PUSH)
cmake_policy(SET CMP0054 NEW) # Only interpret if() arguments as variables or keywords when unquoted

find_path(
	PAM_INCLUDE_DIR
	NAMES "security/pam_appl.h" "pam/pam_appl.h"
)
find_library(
	PAM_LIBRARY
	NAMES "pam"
)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
	PAM
	REQUIRED_VARS PAM_INCLUDE_DIR PAM_LIBRARY
)

if (PAM_FOUND)
	if (NOT TARGET PAM::pam)
		add_library(PAM::pam UNKNOWN IMPORTED)
		set_target_properties(PAM::pam PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PAM_INCLUDE_DIR}")
		set_target_properties(PAM::pam PROPERTIES IMPORTED_LOCATION "${PAM_LIBRARY}")
	endif()
endif()

cmake_policy(POP)

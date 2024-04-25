#pragma once
#include "irods/private/pam/ipam_client.hpp"
#include <string>

namespace PamHandshake
{
    bool pam_auth_check_wrapper(const std::string & application,
                                const std::string & pam_service,
                                IPamClient & client,
                                bool verbose);
}

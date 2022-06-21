#include "irods/authentication_plugin_framework.hpp"

#define USE_SSL 1
#include "irods/sslSockComm.h"

#include "irods/icatHighLevelRoutines.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_auth_constants.hpp"
#include "irods/irods_client_server_negotiation.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_pam_auth_object.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/rcConnect.h"
#include "irods/base64.h"

#include <boost/lexical_cast.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <sys/types.h>
#include <sys/wait.h>

#include <string>
#include <termios.h>
#include <unistd.h>

#include <openssl/md5.h>

#ifdef RODS_SERVER
#include "handshake_session.hpp"
#include "irods/irods_rs_comm_query.hpp"
#include "irods/rsAuthCheck.hpp"
#include "irods/rsAuthRequest.hpp"
#endif

#ifdef RODS_SERVER
const char PAM_STACK_NAME[] = "irods";
const char PAM_CHECKER[] = "/sbin/pam_handshake_auth_check";
const int SESSION_TIMEOUT = 3600;
#endif

void _rsSetAuthRequestGetChallenge( const char* _c );
int get64RandomBytes( char *buf );
void setSessionSignatureClientside( char* _sig );

namespace
{
  using log_auth = irods::experimental::log::authentication;
  namespace irods_auth = irods::experimental::auth;
  using json = nlohmann::json;

  static std::string get_password_from_client_stdin()
  {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tcflag_t oldflag = tty.c_lflag;
    tty.c_lflag &= ~ECHO;
    int error = tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    int errsv = errno;
      
    if (error) {
      printf("WARNING: Error %d disabling echo mode. Password will be displayed in plaintext.", errsv);
    }
    std::string password;
    getline(std::cin, password);
    char new_password[MAX_PASSWORD_LEN + 2]{};
    strncpy(new_password, password.c_str(), MAX_PASSWORD_LEN);
    printf("\n");
    tty.c_lflag = oldflag;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &tty)) {
      printf( "Error reinstating echo mode." );
    }
    return new_password;
  } // get_password_from_client_stdin
} // anonymous namespace

namespace irods
{
  class pam_interactive_authentication : public irods_auth::authentication_base {
  private:
    static constexpr const char* perform_running = "running";
    static constexpr const char* perform_ready = "ready";
    static constexpr const char* perform_waiting = "waiting";
    static constexpr const char* perform_waiting_pw = "waiting_pw";
    static constexpr const char* perform_response = "response";
    static constexpr const char* perform_next = "next";
    static constexpr const char* perform_error = "error";
    static constexpr const char* perform_timeout = "timeout";
    static constexpr const char* perform_authenticated = "authenticated";
    static constexpr const char* perform_not_authenticated = "not_authenticated";

  public:
    pam_interactive_authentication()
    {
      std::cout << "pam_interactive_authentication" << std::endl;
      add_operation(AUTH_CLIENT_AUTH_REQUEST,  OPERATION(rcComm_t, pam_auth_client_request));
      add_operation(AUTH_CLIENT_AUTH_RESPONSE, OPERATION(rcComm_t, pam_auth_response));
      add_operation(perform_running,           OPERATION(rcComm_t, step_client_standard));
      add_operation(perform_ready,             OPERATION(rcComm_t, step_client_standard));
      add_operation(perform_next,              OPERATION(rcComm_t, step_client_standard));
      add_operation(perform_response,          OPERATION(rcComm_t, step_client_standard));
      add_operation(perform_waiting,           OPERATION(rcComm_t, step_waiting));
      add_operation(perform_waiting_pw,        OPERATION(rcComm_t, step_waiting_pw));
      add_operation(perform_error,             OPERATION(rcComm_t, step_error));
      add_operation(perform_timeout,           OPERATION(rcComm_t, step_timeout));
      add_operation(perform_authenticated,     OPERATION(rcComm_t, step_authenticated));
      add_operation(perform_not_authenticated, OPERATION(rcComm_t, step_not_authenticated));
#ifdef RODS_SERVER
      add_operation(AUTH_AGENT_AUTH_REQUEST,   OPERATION(rsComm_t, pam_auth_agent_request));
      add_operation(AUTH_AGENT_AUTH_RESPONSE,  OPERATION(rsComm_t, pam_auth_agent_response));
#endif
        } // ctor

  private:
    json auth_client_start(rcComm_t& comm, const json& req)
    {
      std::cout << "auth_client_start " << req << std::endl;
      json resp{req};
      resp["user_name"] = comm.proxyUser.userName;
      resp["zone_name"] = comm.proxyUser.rodsZone;
      resp[irods_auth::next_operation] = AUTH_CLIENT_AUTH_REQUEST;
      std::cout << std::endl;
      std::cout << resp << std::endl;
      return resp;
    }

    ///////////////////////////////////////////////
    // state REQUEST
    ///////////////////////////////////////////////
    json pam_auth_client_request(rcComm_t& comm, const json& req)
    {
      std::cout << "pam_auth_client_request " << req << std::endl;
      start_ssl(comm);
      json svr_req{req};
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_REQUEST;
      auto res = irods_auth::request(comm, svr_req);

      res[irods_auth::next_operation] =  AUTH_CLIENT_AUTH_RESPONSE;
      return res;      
    }

    json pam_auth_response(rcComm_t&comm, const json& req)
    {
      std::cout << "pam_auth_response " << req << std::endl;
      irods_auth::throw_if_request_message_is_missing_key(req, {"user_name", "zone_name"});
      json svr_req{req};
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      auto resp = irods_auth::request(comm, svr_req);
      return resp;
    }
    


    ///////////////////////////////////////////////
    // state NEXT, RUNNING, READY RESPONSE
    ///////////////////////////////////////////////
    json step_client_standard(rcComm_t& comm, const json& req)
    {
      std::cout << "step_client_standard " << req << std::endl;
      json svr_req{req};
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      auto res = irods_auth::request(comm, svr_req);
      return res;
    }

    ///////////////////////////////////////////////
    // state WAITING
    ///////////////////////////////////////////////
    json step_waiting(rcComm_t& comm, const json& req)
    {
      std::cout << "step_waiting " << req << std::endl;
      std::string input;
      json svr_req{req};
      std::getline (std::cin, input);
      svr_req["resp"] = input;
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      return irods_auth::request(comm, svr_req);
    }

    json step_waiting_pw(rcComm_t& comm, const json& req)
    {
      std::cout << "step_waiting_pw " << req << std::endl;
      std::string pw = get_password_from_client_stdin();
      json svr_req{req};
      svr_req["resp"] = pw;
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      return irods_auth::request(comm, svr_req);
    }

    json step_error(rcComm_t& comm, const json& req)
    {
      std::cout << "step_error " << req << std::endl;
      json res{req};
      res[irods_auth::next_operation] = irods_auth::flow_complete;
      comm.loggedIn = 0;
      return res;
    }

    json step_timeout(rcComm_t& comm, const json& req)
    {
      std::cout << "step_timeout " << req << std::endl;
      json res{req};
      res[irods_auth::next_operation] = irods_auth::flow_complete;
      comm.loggedIn = 0;
      return res;
    }

    json step_authenticated(rcComm_t& comm, const json& req)
    {
      static constexpr const char* auth_scheme_native = "native";
      std::cout << "step_authenticated " << req << std::endl;
      // This operation is basically just running the entire native authentication flow
      // because this is how the PAM authentication plugin has worked historically. This
      // is done in order to minimize communications with the PAM server as iRODS does
      // not use proper "sessions".
      json resp{req};
      const auto& pw = req.at("request_result").get_ref<const std::string&>();
      std::cout << "Save" << std::endl;
      if (const int ec = obfSavePw(0, 0, 0, pw.data()); ec < 0) {
        THROW(ec, "failed to save obfuscated password");
      }

      // The authentication password needs to be removed from the request message as it
      // will send the password over the network without SSL being necessarily enabled.
      resp.erase(irods::AUTH_PASSWORD_KEY);


      rodsEnv env{};
      
      std::strncpy(env.rodsAuthScheme, auth_scheme_native, NAME_LEN);
      irods_auth::authenticate_client(comm, env, json{});

      // If everything completes successfully, the flow is completed and we can
      // consider the user "logged in". Again, the entire native authentication flow
      // was run and so we trust the result.
      resp[irods_auth::next_operation] = irods_auth::flow_complete;

      comm.loggedIn = 1;

      return resp;
    }

    json step_not_authenticated(rcComm_t& comm, const json& req)
    {
      std::cout << "step_not_authenticated " << req << std::endl;
      json res{req};
      res[irods_auth::next_operation] = irods_auth::flow_complete;
      comm.loggedIn = 0;
      return res;
    }

#ifdef RODS_SERVER
    int get_ttl(const json & req)
    {
      int ttl = 0;
      if (req.contains(irods::AUTH_TTL_KEY)) {
        if (const auto& ttl_str = req.at(irods::AUTH_TTL_KEY).get_ref<const std::string&>(); !ttl_str.empty()) {
          try {
            ttl = boost::lexical_cast<int>(ttl_str);
          }
          catch (const boost::bad_lexical_cast& e) {
            THROW(SYS_INVALID_INPUT_PARAM, fmt::format("invalid TTL [{}]", ttl_str));
          }
        }
      }
      return ttl;
    }
#endif

#ifdef RODS_SERVER
    json pam_auth_agent_request(rsComm_t& comm, const json& req)
    {
      json resp{req};
      const auto username = req.at("user_name").get_ref<const std::string&>();
      int ttl = get_ttl(req);
      char password_out[MAX_NAME_LEN]{};
      char* pw_ptr = &password_out[0];

      const int ec = chlUpdateIrodsPamPassword(&comm, const_cast<char*>(username.c_str()), ttl, nullptr, &pw_ptr);
      if (ec < 0) {
        THROW(ec, "failed updating iRODS pam password");
      }
      resp["request_result"] = password_out;

      if (comm.auth_scheme) {
        free(comm.auth_scheme);
      }

      comm.auth_scheme = strdup("pam_interactive");
      return resp;
    } // native_auth_agent_request
#endif

#ifdef RODS_SERVER
    json pam_auth_agent_response(rsComm_t& comm, const json& req)
    {
      using log_auth = irods::experimental::log::authentication;
      using Session = PamHandshake::Session;
      const std::vector<std::string_view> required_keys{"user_name", "zone_name"};
      irods_auth::throw_if_request_message_is_missing_key(req, required_keys);

      rodsServerHost_t* host = nullptr;

      log_auth::trace("connecting to catalog provider");
      if (const int ec = getAndConnRcatHost(&comm, PRIMARY_RCAT,
                                            comm.clientUser.rodsZone,
                                            &host); ec < 0) {
        THROW(ec, "getAndConnRcatHost failed.");
      }
      if (LOCAL_HOST != host->localFlag)
      {
        const auto disconnect = irods::at_scope_exit{[host]
                                                     {
                                                       rcDisconnect(host->conn);
                                                       host->conn = nullptr;
                                                     }
        };
        log_auth::trace("redirecting call to CSP");
#if USE_SSL
        if (const auto ec = sslStart(host->conn); ec) {
          THROW(ec, "could not establish SSL connection");
        }

        const auto end_ssl = irods::at_scope_exit{[host] { sslEnd(host->conn); }};
#endif
        return irods_auth::request(*host->conn, req);
      }

      auto session = Session::getSingleton(PAM_STACK_NAME,
                                           PAM_CHECKER,
                                           SESSION_TIMEOUT);
      auto p = session->pull(0, 0);

      json resp{req};
      resp[irods_auth::next_operation] = Session::StateToString(p.first);
      resp["msg"] = p.second;
      return resp;
    }
#endif
    
  private:
    void start_ssl(rcComm_t& comm)
    {
      // Need to enable SSL here if it is not already being used because the PAM password
      // is sent to the server in the clear.
#if USE_SSL
      const bool using_ssl = irods::CS_NEG_USE_SSL == comm.negotiation_results;
      const auto end_ssl_if_we_enabled_it = irods::at_scope_exit{[&comm, using_ssl] {
          if (!using_ssl)  {
            sslEnd(&comm);
          }
        }};
      if (using_ssl) {
        if (const int ec = sslStart(&comm); ec) {
          THROW(ec, "failed to enable SSL");
        }
      }
#endif
    }
  }; // class pam_authentication
} // namespace irods


extern "C"
irods::pam_interactive_authentication* plugin_factory(const std::string&, const std::string&)
{
  return new irods::pam_interactive_authentication{};
}



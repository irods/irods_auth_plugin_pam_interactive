#include <irods/authentication_plugin_framework.hpp>

#include <irods/icatHighLevelRoutines.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_auth_constants.hpp>
#include <irods/irods_client_server_negotiation.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_pam_auth_object.hpp>
#include <irods/miscServerFunct.hpp>
#include <irods/rcConnect.h>
#include <irods/base64.hpp>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <sys/types.h>
#include <sys/wait.h>

#include <chrono>
#include <string>

#include <termios.h>
#include <unistd.h>

#ifdef RODS_SERVER
#include "irods/private/pam/handshake_session.hpp"
#include "irods/private/pam/pam_interactive_plugin_logging_category.hpp"

#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_default_paths.hpp>
#include <irods/irods_rs_comm_query.hpp>
#include <irods/irods_server_properties.hpp>
#include <irods/rsAuthCheck.hpp>
#include <irods/rsAuthRequest.hpp>
#include <irods/rs_get_grid_configuration_value.hpp>
#include <irods/scoped_privileged_client.hpp>

#include <fmt/ranges.h> // for fmt::join
#endif

namespace
{
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

#ifdef RODS_SERVER
    // Only define log_pam for server-side plugin because clients should not attempt to write to the server log.
    using log_pam = irods::experimental::log::logger<pam_interactive_auth_plugin_logging_category>;
    namespace fs = boost::filesystem;

    // TODO(irods/irods#7937): We can use irods::KW_CFG_PLUGIN_TYPE_AUTHENTICATION once its value is not "auth".
    constexpr const char* AUTHENTICATION_CONFIG_KW = "authentication";

    auto get_pam_checker_program() -> const fs::path&
    {
        static const auto pam_checker{
            irods::get_irods_default_plugin_directory() / "auth" / "pam_handshake_auth_check"};
        return pam_checker;
    } // get_pam_checker_program
#endif // RODS_SERVER
} // anonymous namespace

namespace irods
{
  class pam_interactive_authentication : public irods_auth::authentication_base {
  private:
#ifdef RODS_SERVER
    using Session = PamHandshake::Session;
#endif
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
    static constexpr const char* perform_native_auth = "native_auth";
   
    static constexpr const char* pam_interactive_scheme = "pam_interactive";

  public:
    pam_interactive_authentication()
    {
      add_operation(AUTH_CLIENT_AUTH_REQUEST,  OPERATION(rcComm_t, pam_auth_client_request));
      add_operation(AUTH_CLIENT_AUTH_RESPONSE, OPERATION(rcComm_t, pam_auth_response));
      add_operation(perform_running,           OPERATION(rcComm_t, step_client_running));
      add_operation(perform_ready,             OPERATION(rcComm_t, step_client_ready));
      add_operation(perform_next,              OPERATION(rcComm_t, step_client_next));
      add_operation(perform_response,          OPERATION(rcComm_t, step_client_response));
      add_operation(perform_waiting,           OPERATION(rcComm_t, step_waiting));
      add_operation(perform_waiting_pw,        OPERATION(rcComm_t, step_waiting_pw));
      add_operation(perform_error,             OPERATION(rcComm_t, step_error));
      add_operation(perform_timeout,           OPERATION(rcComm_t, step_timeout));
      add_operation(perform_authenticated,     OPERATION(rcComm_t, step_authenticated));
      add_operation(perform_not_authenticated, OPERATION(rcComm_t, step_not_authenticated));
      add_operation(perform_native_auth,       OPERATION(rcComm_t, auth_client_perform_native_auth));
#ifdef RODS_SERVER
      add_operation(AUTH_AGENT_AUTH_REQUEST,   OPERATION(rsComm_t, pam_auth_agent_request));
      add_operation(AUTH_AGENT_AUTH_RESPONSE,  OPERATION(rsComm_t, pam_auth_agent_response));
#endif
        } // ctor

  private:
    
    // Apply patch to the persistence state.
    void patch_state(nlohmann::json & req) {
      if(req["msg"].contains("patch")) {
        nlohmann::json & patch(req["msg"]["patch"]);
        for(auto & it : patch) {
         std::string op(it.value("op", std::string("")));
         if(op == "add" || op == "replace") {
            if(!it.contains("value")) {
              it["value"] = req.value("resp", std::string(""));
            }
          }
        }
        req["pstate"] = req["pstate"].patch(patch);
        req["pdirty"] = true;
        req["msg"].erase("patch");
      }
    }

    // initialize the persistence state of the PAM stack
    void initialize_state(json& resp) {
      resp["pdirty"] = false;
      resp["pstate"] = "{}"_json;
      std::string file_name(pam_auth_file_name());
      std::ifstream file(file_name.c_str());
      if (file.is_open()) {
        file >> resp["pstate"];
        file.close();
      }
    }

    // returns true if iinit context
    bool check_force_prompt(const json & req) const {
      const auto force_prompt = req.find(irods_auth::force_password_prompt);
      if (req.end() != force_prompt && force_prompt->get<bool>()) {
        return true; 
      }
      return false;
    }

    auto auth_client_start(rcComm_t& comm, const json& req) -> json
    {
        json resp{req};
        initialize_state(resp);
        resp["user_name"] = comm.proxyUser.userName;
        resp["zone_name"] = comm.proxyUser.rodsZone;

        // The force_password_prompt keyword does not check for an existing password but instead forcibly displays the
        // authentication prompt(s). This is useful when a client like iinit wants to "reset" the user's authentication
        // "session" but in general other clients want to use the already-authenticated "session."
        if (!check_force_prompt(resp)) {
            // obfGetPw returns 0 if the password is retrieved successfully. Therefore, we do NOT need to
            // re-authenticate with PAM in this case. This being the case, we conclude that the user has already been
            // authenticated via PAM with the server. We proceed with steps for native authentication which will use the
            // stored, limited password.
            if (const bool need_password = obfGetPw(nullptr); !need_password) {
                resp[irods_auth::next_operation] = perform_native_auth;
                return resp;
            }
        }

        resp[irods_auth::next_operation] = AUTH_CLIENT_AUTH_REQUEST;
        return resp;
    } // auth_client_start

    // get default value from local state
    std::string get_default_value(const json& req) {
      std::string default_path = req["msg"].value("default_path", std::string());
      std::string default_value;
      if(!default_path.empty()) {
        json::json_pointer jptr(default_path);
        if(req["pstate"].contains(jptr)) {
          default_value = req["pstate"].at(jptr).get<std::string>();
        }
      }
      return default_value;
    }

    bool retrieve_entry(json& req) {
      // get entry from local store and add the value to resp field
      if(req["msg"].contains("retrieve")) {
        std::string retr_path = req["msg"].value("retrieve", std::string(""));
        if(!retr_path.empty()) {
        json::json_pointer jptr(retr_path);
        if(req["pstate"].contains(jptr)) {
            req["resp"] = req["pstate"].at(jptr).get<std::string>();
            return true;
          }
        }
        req["resp"] = "";
        return true; 
      }
      return false;
    }

    ///////////////////////////////////////////////
    // state REQUEST
    ///////////////////////////////////////////////
    json pam_auth_client_request(rcComm_t& comm, const json& req) {
      json svr_req{req};
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_REQUEST;
      auto res = irods_auth::request(comm, svr_req);
      res[irods_auth::next_operation] =  AUTH_CLIENT_AUTH_RESPONSE;
      return res;      
    }

    json pam_auth_response(rcComm_t&comm, const json& req) {
      irods_auth::throw_if_request_message_is_missing_key(req, {"user_name", "zone_name"});
      json svr_req{req};
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      auto resp = irods_auth::request(comm, svr_req);
      return resp;
    }

    ///////////////////////////////////////////////
    // state NEXT
    ///////////////////////////////////////////////
    json step_client_next(rcComm_t& comm, const json& req) {
      std::string prompt = req["msg"].value("prompt", std::string(""));
      if(!prompt.empty()) {
        std::cout << prompt << std::endl << std::flush;
      }
      json svr_req{req};
      patch_state(svr_req);
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      return irods_auth::request(comm, svr_req);
    }

    ///////////////////////////////////////////////
    // state RUNNING
    ///////////////////////////////////////////////
    json step_client_running(rcComm_t& comm, const json& req) {
      json svr_req{req};
      patch_state(svr_req);
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      return irods_auth::request(comm, svr_req);
    }

    ///////////////////////////////////////////////
    // state READY
    ///////////////////////////////////////////////
    json step_client_ready(rcComm_t& comm, const json& req) {
      json svr_req{req};
      patch_state(svr_req);
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      return irods_auth::request(comm, svr_req);
    }

    ///////////////////////////////////////////////
    // state RESPONSE
    ///////////////////////////////////////////////
    json step_client_response(rcComm_t& comm, const json& req) {
      json svr_req{req};
      patch_state(svr_req);
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      return irods_auth::request(comm, svr_req);
    }

    ///////////////////////////////////////////////
    // state WAITING
    //
    // wait for user input and send the result back to server
    ///////////////////////////////////////////////
    json step_waiting(rcComm_t& comm, const json& req)
    {
      std::string input;
      json svr_req{req};
      if(retrieve_entry(svr_req)) {
        svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;  
        patch_state(svr_req);
        return irods_auth::request(comm, svr_req);
      }
     
      std::string prompt = req["msg"].value("prompt", std::string(""));
      std::string default_value = get_default_value(req);
      if(default_value.empty()) {
        std::cout << prompt << " " << std::flush;
      }
      else {
        std::cout << prompt << "[" << default_value << "] " << std::flush;
      }
      std::getline (std::cin, input);
      input.erase(remove_if(input.begin(), input.end(), isspace), input.end());
      if(input.empty()) {
        svr_req["resp"] = default_value;
      }
      else { 
        svr_req["resp"] = input;
      }
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;  
      patch_state(svr_req);
      return irods_auth::request(comm, svr_req);
    }

    ///////////////////////////////////////////////
    // state WAITING_PW
    //
    // wait for user password input and send the result back to server
    ///////////////////////////////////////////////
    json step_waiting_pw(rcComm_t& comm, const json& req) {
      json svr_req{req};
      if(retrieve_entry(svr_req)) {
        svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;  
        patch_state(svr_req);
        return irods_auth::request(comm, svr_req);
      }
      std::string prompt = req["msg"].value("prompt", std::string(""));
      std::string default_value = get_default_value(req);
      if(default_value.empty()) {
        std::cout << prompt << " " << std::flush;
      }
      else {
        std::cout << prompt << "[******] " << std::flush;
      }
      std::string pw = get_password_from_client_stdin();
     
      if(pw.empty()) {
        svr_req["resp"] = default_value;
      }
      else { 
        svr_req["resp"] = pw;
      }
      patch_state(svr_req);
      svr_req[irods_auth::next_operation] = AUTH_AGENT_AUTH_RESPONSE;
      return irods_auth::request(comm, svr_req);
    }

    json step_error(rcComm_t& comm, const json& req) {
      std::cout << "error " << std::endl;
      json res{req};
      res[irods_auth::next_operation] = irods_auth::flow_complete;
      comm.loggedIn = 0;
      return res;
    }

    json step_timeout(rcComm_t& comm, const json& req) {
      std::cout << "timeout" << std::endl;
      json res{req};
      res[irods_auth::next_operation] = irods_auth::flow_complete;
      comm.loggedIn = 0;
      return res;
    }

    // determine file name of persistent state file
    std::string pam_auth_file_name() const {
      char *authfilename = getRodsEnvAuthFileName();
      if(authfilename && *authfilename != '\0') {
        return std::string(authfilename) + ".json";
      }
      else {
        return std::string(getenv( "HOME" )) + "/.irods/.irodsA.json";
      }
    }

    void save_state_to_file(const json& resp) {

      json pstate{};

      std::string file_name(pam_auth_file_name());
      // open file in 0600 mode
      int fd = obfiOpenOutFile(file_name.c_str(), 0);
      if ( fd < 0 ) {
        throw std::runtime_error((std::string("cannot write to  file ") + file_name).c_str());
      }
      std::stringstream ss;
      ss << pstate << std::flush;
      int write_res = obfiWritePw(fd, ss.str().c_str());
      close(fd);
      if(write_res < 0 ) {
        throw std::runtime_error((std::string("cannot write to  file ") + file_name).c_str());
      }
    }

    json step_authenticated(rcComm_t& comm, const json& req) {
      // This operation is basically just running the entire native authentication flow
      // because this is how the PAM authentication plugin has worked historically. This
      // is done in order to minimize communications with the PAM server as iRODS does
      // not use proper "sessions".
      json resp{req};
      const auto& pw = req.at("request_result").get_ref<const std::string&>();
      if (const int ec = obfSavePw(0, 0, 0, pw.data()); ec < 0) {
        THROW(ec, "failed to save obfuscated password");
      }
      save_state_to_file(resp);
      resp[irods_auth::next_operation] = perform_native_auth; 
      return resp;
    }
    
    json auth_client_perform_native_auth(rcComm_t& comm, const json& req) {
      // This operation is basically just running the entire native authentication flow
      // because this is how the PAM authentication plugin has worked historically. This
      // is done in order to minimize communications with the PAM server as iRODS does
      // not use proper "sessions".
      json resp{req};

      // The authentication password needs to be removed from the request message as it
      // will send the password over the network without TLS/SSL being necessarily enabled.
      resp.erase(irods::AUTH_PASSWORD_KEY);

      static constexpr const char* auth_scheme_native_str = "native";
      rodsEnv env{};
      std::strncpy(env.rodsAuthScheme, auth_scheme_native_str, NAME_LEN);
      irods_auth::authenticate_client(comm, env, json{});

      // If everything completes successfully, the flow is completed and we can
      // consider the user "logged in". Again, the entire native authentication flow
      // was run and so we trust the result.
      resp[irods_auth::next_operation] = irods_auth::flow_complete;

      comm.loggedIn = 1;

      return resp;
    }

    json step_not_authenticated(rcComm_t& comm, const json& req) {
      json res{req};
      res[irods_auth::next_operation] = irods_auth::flow_complete;
      comm.loggedIn = 0;
      return res;
    }

#ifdef RODS_SERVER
    auto pam_auth_agent_request(rsComm_t& comm, const json& req) -> json
    {
        // Set the auth scheme for the agent connection to pam_interactive.
        if (comm.auth_scheme) {
            std::free(comm.auth_scheme);
        }
        comm.auth_scheme = strdup(pam_interactive_scheme);

        // Set the log level for the pam_interactive plugin's log category.
        constexpr const char* CFG_LOG_LEVEL_CATEGORY_PAM_INTERACTIVE_AUTH_PLUGIN_KW = "pam_interactive_auth_plugin";
        log_pam::set_level(
            irods::experimental::log::get_level_from_config(CFG_LOG_LEVEL_CATEGORY_PAM_INTERACTIVE_AUTH_PLUGIN_KW));

        // Make sure the connection is secured before proceeding. If the connection is not secure, a warning will be
        // displayed in the server log at the very least. If the plugin is not configured to allow for insecure
        // communications between the client and server, the authentication attempt is rejected outright.
        if (irods::CS_NEG_USE_SSL != comm.negotiation_results) {
            if (require_secure_communications()) {
                THROW(SYS_NOT_ALLOWED,
                      "Client communications with this server are not secure and this authentication plugin is "
                      "configured to require TLS/SSL communication. Authentication is not allowed unless this server "
                      "is configured to require TLS/SSL in order to prevent leaking sensitive user information.");
            }
            log_pam::warn("Client communications with this server are not secure, and sensitive user information is "
                          "being communicated over the network in an unencrypted manner. Configure this server to "
                          "require TLS/SSL to prevent security leaks.");
        }

        // The catalog service provider will be conducting the PAM conversation as well as authenticating the user with
        // iRODS. We need to redirect at this point to get the catalog service provider's agent set up as well, if this
        // connection is not already on a catalog service provider.
        rodsServerHost_t* host = nullptr;
        log_pam::trace("Connecting to catalog service provider");
        if (const int ec = getAndConnRcatHost(&comm, PRIMARY_RCAT, comm.clientUser.rodsZone, &host); ec < 0) {
            THROW(ec, "getAndConnRcatHost failed.");
        }
        if (LOCAL_HOST != host->localFlag) {
            // In addition to the client-server connection, the server-to-server connection which occurs between the
            // local server and the catalog service provider must be secured as well. If the connection is not secure,
            // a warning will be displayed in the server log at the very least. If the plugin is not configured to
            // allow for insecure communications between the client (in this case, also a server) and server, the
            // authentication attempt is rejected outright.
            if (irods::CS_NEG_USE_SSL != host->conn->negotiation_results) {
                if (require_secure_communications()) {
                    THROW(SYS_NOT_ALLOWED,
                          "Server-to-server communications with the catalog service provider server are not secure and "
                          "this authentication plugin is configured to require TLS/SSL communication. Authentication "
                          "is not allowed unless this server is configured to require TLS/SSL in order to prevent "
                          "leaking sensitive user information.");
                }
                log_pam::warn("Server-to-server communications with the catalog service provider server are not "
                              "secure, and sensitive user information is being communicated over the network in an "
                              "unencrypted manner. Configure this server to require TLS/SSL to prevent security "
                              "leaks.");
            }
            // Note: We should not disconnect this server-to-server connection because the connection is not owned by
            // this context. A set of server-to-server connections is maintained by the server agent and reused by
            // various APIs and operations as needed.
            return irods_auth::request(*host->conn, req);
        }

        // This operation does not have anything to add to the JSON structure, so just copy the request structure.
        return req;
    } // native_auth_agent_request
#endif

#ifdef RODS_SERVER
    auto pam_auth_agent_response(rsComm_t& comm, const json& req) -> json
    {
        // Make sure the connection is secured before proceeding. If the connection is not secure, a warning will be
        // displayed in the server log at the very least. If the plugin is not configured to allow for insecure
        // communications between the client and server, the authentication attempt is rejected outright.
        if (irods::CS_NEG_USE_SSL != comm.negotiation_results) {
            if (require_secure_communications()) {
                THROW(SYS_NOT_ALLOWED,
                      "Client communications with this server are not secure and this authentication plugin is "
                      "configured to require TLS/SSL communication. Authentication is not allowed unless this server is "
                      "configured to require TLS/SSL in order to prevent leaking sensitive user information.");
            }
            log_pam::warn("Client communications with this server are not secure, and sensitive user information is "
                          "being communicated over the network in an unencrypted manner. Configure this server to "
                          "require TLS/SSL to prevent security leaks.");
        }

      const std::vector<std::string_view> required_keys{"user_name", "zone_name"};
      irods_auth::throw_if_request_message_is_missing_key(req, required_keys);

      // The catalog service provider will be conducting the PAM conversation as well as authenticating the user with
      // iRODS. We need to redirect at this point as it is required for the PAM conversation to work correctly.
      rodsServerHost_t* host = nullptr;
      log_pam::trace("Connecting to catalog service provider");
      if (const int ec = getAndConnRcatHost(&comm, PRIMARY_RCAT, comm.clientUser.rodsZone, &host); ec < 0) {
          THROW(ec, "getAndConnRcatHost failed.");
      }
      if (LOCAL_HOST != host->localFlag) {
          log_pam::trace("Redirecting call to catalog service provider");
          // In addition to the client-server connection, the server-to-server connection which occurs between the
          // local server and the catalog service provider must be secured as well. If the connection is not secure,
          // a warning will be displayed in the server log at the very least. If the plugin is not configured to
          // allow for insecure communications between the client (in this case, also a server) and server, the
          // authentication attempt is rejected outright.
          if (irods::CS_NEG_USE_SSL != host->conn->negotiation_results) {
              if (require_secure_communications()) {
                  THROW(SYS_NOT_ALLOWED,
                        "Server-to-server communications with the catalog service provider server are not secure and "
                        "this authentication plugin is configured to require TLS/SSL communication. Authentication is "
                        "not allowed unless this server is configured to require TLS/SSL in order to prevent leaking "
                        "sensitive user information.");
              }
              log_pam::warn("Server-to-server communications with the catalog service provider server are not secure, "
                            "and sensitive user information is being communicated over the network in an unencrypted "
                            "manner. Configure this server to require TLS/SSL to prevent security leaks.");
          }
          // Note: We should not disconnect this server-to-server connection because the connection is not owned by
          // this context. A set of server-to-server connections is maintained by the server agent and reused by
          // various APIs and operations as needed.
          return irods_auth::request(*host->conn, req);
      }
      constexpr int SESSION_TIMEOUT = 3600;
      const auto pam_stack_name = get_pam_stack_name_from_configuration();
      auto session = Session::getSingleton(
          pam_stack_name, get_pam_checker_program().c_str(), comm.clientUser.userName, SESSION_TIMEOUT);

      std::string resp_str(req.value("resp", std::string("")));

      auto p = session->pull(resp_str.c_str(), resp_str.size());
      json resp{req};
      if (p.first == Session::State::Authenticated) {
          log_pam::trace("Generating random password for iRODS");
          int ttl = 0;
          if (req.contains(irods::AUTH_TTL_KEY)) {
              if (const auto& ttl_str = req.at(irods::AUTH_TTL_KEY).get_ref<const std::string&>(); !ttl_str.empty()) {
                  try {
                      ttl = boost::lexical_cast<int>(ttl_str);
                      log_pam::trace("{}:{} - TTL value: [{}]", __func__, __LINE__, ttl);
                  }
                  catch (const boost::bad_lexical_cast& e) {
                      THROW(SYS_INVALID_INPUT_PARAM, fmt::format("invalid TTL [{}]", ttl_str));
                  }
              }
          }

          const auto& username = req.at("user_name").get_ref<const std::string&>();

          // Plus 1 for null terminator.
          std::array<char, MAX_PASSWORD_LEN + 1> password_out{};
          char* password_ptr = password_out.data();
          const int ec =
              chlUpdateIrodsPamPassword(&comm, username.c_str(), ttl, nullptr, &password_ptr, password_out.size());
          if (ec < 0) {
              THROW(ec, "failed updating iRODS pam password");
          }
          resp["request_result"] = password_out.data();
      }
      resp[irods_auth::next_operation] = Session::StateToString(p.first);
      if(p.second.empty() || p.second[0] != '{') {
        // PAM stack does not return a json string
        if(p.first == Session::State::WaitingPw || p.first == Session::State::Waiting ) {
          std::string prompt = p.second;
          if(prompt.empty()) {
            if(p.first == Session::State::WaitingPw) {
              prompt = "password";
            }
            else {
              prompt = "login";
            }
          }
          std::string path = std::string("/") + prompt;
          // create the JSON message:
          // 1. dispaly a prompt
          // 2. patch the local state with the response
          resp["msg"] = { {"prompt", prompt},
                          {"password", (p.first == Session::State::WaitingPw)},
                          {"default_path", path},
                          {"patch", {
                            {{"op", "add"}, {"path", path}}}}};
        }
        else {
          // create the JSON message:
          // Display the message sent from the server
          std::string path = p.second.empty() ? "/value" : std::string("/") + p.second;
          resp["msg"] = {{"prompt", p.second}};
        }
      }
      else {
        // PAM stack returns a json string.
        // we parse it and set the message
        resp["msg"] = nlohmann::json::parse(p.second, nullptr, true);  
      }
      return resp;
    }

    static auto require_secure_communications() -> bool
    {
        constexpr const char* KW_CFG_PAM_INTERACTIVE_INSECURE_MODE = "insecure_mode";
        static const auto config_path = irods::configuration_parser::key_path_t{
            irods::KW_CFG_PLUGIN_CONFIGURATION,
            AUTHENTICATION_CONFIG_KW,
            irods::pam_interactive_authentication::pam_interactive_scheme,
            KW_CFG_PAM_INTERACTIVE_INSECURE_MODE};
        try {
            // Return the negation of the configuration's value because the configuration is "insecure_mode", but this
            // function is named "require_secure_communications", which is the opposite. So, if insecure_mode is set to
            // true, we should return false for "require_secure_communications"; and vice-versa.
            return !irods::get_server_property<const bool>(config_path);
        }
        catch (const irods::exception& e) {
            if (KEY_NOT_FOUND == e.code()) {
                // If the plugin configuration is not set, default to requiring secure communications.
                return true;
            }
            // Re-throw for any other error.
            throw;
        }
        catch (const json::exception e) {
            THROW(CONFIGURATION_ERROR,
                fmt::format("Error occurred while attempting to get the value of server configuration [{}]: {}",
                            fmt::join(config_path, "."), e.what()));
        }
    } // require_secure_communications

    static auto get_pam_stack_name_from_configuration() -> std::string
    {
        constexpr const char* KW_CFG_PAM_INTERACTIVE_PAM_STACK_NAME = "pam_stack_name";
        static const auto config_path = irods::configuration_parser::key_path_t{
            irods::KW_CFG_PLUGIN_CONFIGURATION,
            AUTHENTICATION_CONFIG_KW,
            irods::pam_interactive_authentication::pam_interactive_scheme,
            KW_CFG_PAM_INTERACTIVE_PAM_STACK_NAME};
        try {
            return irods::get_server_property<const std::string>(config_path);
        }
        catch (const irods::exception& e) {
            if (KEY_NOT_FOUND == e.code()) {
                // If the plugin configuration is not set, default to "irods".
                return "irods";
            }
            // Re-throw for any other error.
            throw;
        }
        catch (const json::exception e) {
            THROW(CONFIGURATION_ERROR,
                fmt::format("Error occurred while attempting to get the value of server configuration [{}]: {}",
                            fmt::join(config_path, "."), e.what()));
        }
    } // get_pam_stack_name_from_configuration
#endif
  }; // class pam_authentication
} // namespace irods

extern "C"
irods::pam_interactive_authentication* plugin_factory(const std::string&, const std::string&) {
  return new irods::pam_interactive_authentication{};
}

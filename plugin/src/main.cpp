#include <irods/authentication_plugin_framework.hpp>

#define USE_SSL 1
#include <irods/sslSockComm.h>

#include <irods/icatHighLevelRoutines.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_auth_constants.hpp>
#include <irods/irods_client_server_negotiation.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_pam_auth_object.hpp>
#include <irods/miscServerFunct.hpp>
#include <irods/rcConnect.h>
#include <irods/base64.hpp>

#include <boost/lexical_cast.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <sys/types.h>
#include <sys/wait.h>

#include <chrono>
#include <string>

#include <termios.h>
#include <unistd.h>

#include <openssl/md5.h>

#ifdef RODS_SERVER
#include "irods/private/pam/handshake_session.hpp"

#include <irods/irods_rs_comm_query.hpp>
#include <irods/rsAuthCheck.hpp>
#include <irods/rsAuthRequest.hpp>
#include <irods/irods_server_properties.hpp>
#endif

#ifdef RODS_SERVER
const char PAM_STACK_NAME[] = "irods";
const char PAM_CHECKER[] = "/usr/lib/irods/plugins/auth/pam_handshake_auth_check";
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
   
    //offset between the TTL in the database and the expiration time in the local json document
    static constexpr const int pam_time_to_live_offset = 60;

    // pam entry in json document is valid for this amount of seconds
    // this value can be overwritten with the --ttl option of iinit
    // and the password min time if the server_config.json
    static constexpr const int pam_time_to_live_default = 3600;

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
      if(!resp["pstate"].contains("__expire__")) {

      }
    }

    // return true, if the configuration is still valid
    bool is_pam_valid(const json & resp) {
      // return false if expiration date > now or not set
      std::string expire_str = resp["pstate"].value("__expire__", std::string(""));
      if(!expire_str.empty()) {
        std::istringstream ss(expire_str);
	
        std::tm t = {};
        // Using epoch seconds to check expiration 
	long long int expire_epoch;
        ss >> expire_epoch;
	if (expire_epoch <= 0) {
	  throw std::runtime_error(std::string("failed to parse expiration timestamp:'") + expire_str + "'");
	}
	
	// now time point
	std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
	
	// compare epoch timestamps to determine validity session
	if (std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count() < expire_epoch ){
	  
          return true;
        }
      }
      return false;
    }

    // add the expiration time to the persistent state
    void add_pam_expiration(json & resp) {
      int ttl_seconds = resp.value<int>("ttl_seconds", 0);
      // make sure that ttl on the client side expires before
      // the entry on the server.
      // In this way the user is sent to usual pam_interactive flow iinit instead of 
      // just getting an authentication error
      // The TTL is also checked in the backend
      ttl_seconds-= pam_time_to_live_offset;
      if(ttl_seconds < 0) {
        ttl_seconds = 0;
      }
      if(ttl_seconds == 0) {
        ttl_seconds = pam_time_to_live_default;
      }

      std::ostringstream ss;

      // now time point
      std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
      
      // make expiration timestamp by adding ttl to current timestamp
      // using std::chrono durations
      ss << std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count() + std::chrono::seconds{ttl_seconds}.count() << std::flush;
      
      resp["pstate"]["__expire__"] = ss.str();
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
        static constexpr const char* auth_scheme_native = "native";
        json resp{req};
        initialize_state(resp);
        resp["user_name"] = comm.proxyUser.userName;
        resp["zone_name"] = comm.proxyUser.rodsZone;

        // The force_password_prompt keyword does not check for an existing password but instead forcibly displays the
        // authentication prompt(s). This is useful when a client like iinit wants to "reset" the user's authentication
        // "session" but in general other clients want to use the already-authenticated "session."
        if (!check_force_prompt(resp) && is_pam_valid(resp)) {
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
      start_ssl(comm);
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

      json pstate{ {"__expire__", resp["pstate"].value("__expire__", "") } };

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
      static constexpr const char* auth_scheme_native = "native";
      // This operation is basically just running the entire native authentication flow
      // because this is how the PAM authentication plugin has worked historically. This
      // is done in order to minimize communications with the PAM server as iRODS does
      // not use proper "sessions".
      json resp{req};
      const auto& pw = req.at("request_result").get_ref<const std::string&>();
      if (const int ec = obfSavePw(0, 0, 0, pw.data()); ec < 0) {
        THROW(ec, "failed to save obfuscated password");
      }
      add_pam_expiration(resp);
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
      // will send the password over the network without SSL being necessarily enabled.
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
    json pam_auth_agent_request(rsComm_t& comm, const json& req) {
      json resp{req};
      if (comm.auth_scheme) {
        free(comm.auth_scheme);
      }

      comm.auth_scheme = strdup(pam_interactive_scheme);
      return resp;
    } // native_auth_agent_request
#endif

#ifdef RODS_SERVER
    int get_int_from_server_config(const json::json_pointer& jptr) const
    {
        const auto config_handle = irods::server_properties::instance().map();
        const auto& config_json = config_handle.get_json();
        if (const auto itr = config_json.find(jptr); std::end(config_json) != itr) {
            return itr->get<int>();
        }

        return 0;
    }

    int get_min_ttl_from_server_config() const {
      static json::json_pointer jptr("/plugin_configuration/authentication/pam_interactive/password_min_time"_json_pointer);
      return get_int_from_server_config(jptr);
    }

    int get_max_ttl_from_server_config() const {
      static json::json_pointer jptr("/plugin_configuration/authentication/pam_interactive/password_max_time"_json_pointer);
      return get_int_from_server_config(jptr);
      
    }

    void  pam_generate_password(rsComm_t& comm, json& resp) {
      // Todo: allow TTL in granularity smaller than 3600 seconds
      // The limit is imposed by the chlUpdateIrodsPamPassword function which accepts TTLs as hours
      const auto username = resp.at("user_name").get_ref<const std::string&>();
      // seconds
      int min_ttl = get_min_ttl_from_server_config();
      int max_ttl = get_max_ttl_from_server_config();
      if(min_ttl > 0 && min_ttl < 3600) {
        // the smallest unit is one hour (accepted by chlUpdateIrodsPamPassword)
        throw std::range_error("password_min_time is not allowed to be smaller than 3600 seconds");
      }
      if(max_ttl > 0 && max_ttl < 3600) {
        // the smallest unit is one hour (accepted by chlUpdateIrodsPamPassword)
        throw std::range_error("password_max_time is not allowed to be smaller than 3600 seconds");
      }
      // the unit of ttl is hours
      int ttl = 0;
      if (resp.contains(irods::AUTH_TTL_KEY)) {
        if (const auto& ttl_str = resp.at(irods::AUTH_TTL_KEY).get_ref<const std::string&>(); !ttl_str.empty()) {
          try {
            ttl = boost::lexical_cast<int>(ttl_str);
          }
          catch (const boost::bad_lexical_cast& e) {
            THROW(SYS_INVALID_INPUT_PARAM, fmt::format("invalid TTL [{}]", ttl_str));
          }
        }
      }

      int ttl_seconds = ttl * 3600;
      if(min_ttl > 0) {
        if(ttl_seconds < min_ttl) {
          ttl_seconds = min_ttl;
        }
      }
      if(max_ttl > 0) {
        if(ttl_seconds > max_ttl) {
          ttl_seconds = max_ttl;
        }
      }
      ttl = ttl_seconds / 3600;
      ttl_seconds = ttl * 3600;
      char password_out[MAX_PASSWORD_LEN+1]{};
      char* pw_ptr = &password_out[0];
      const int ec = chlUpdateIrodsPamPassword(&comm, username.c_str(), ttl, nullptr, &pw_ptr, sizeof(password_out));
      if (ec < 0) {
        THROW(ec, "failed updating iRODS pam password");
      }
      resp["request_result"] = password_out;
      resp["ttl_seconds"] = ttl_seconds;
    }

    json pam_auth_agent_response(rsComm_t& comm, const json& req) {
      using log_auth = irods::experimental::log::authentication;
      const std::vector<std::string_view> required_keys{"user_name", "zone_name"};
      irods_auth::throw_if_request_message_is_missing_key(req, required_keys);

      rodsServerHost_t* host = nullptr;
      log_auth::trace("connecting to catalog provider");
      if (const int ec = getAndConnRcatHost(&comm, PRIMARY_RCAT,
                                            comm.clientUser.rodsZone,
                                            &host); ec < 0) {
        THROW(ec, "getAndConnRcatHost failed.");
      }
      if (LOCAL_HOST != host->localFlag) {
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
					   comm.clientUser.userName,
                                           SESSION_TIMEOUT);

      std::string resp_str(req.value("resp", std::string("")));

      auto p = session->pull(resp_str.c_str(), resp_str.size());
      json resp{req};
      if(p.first == Session::State::Authenticated) {
        pam_generate_password(comm, resp);
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
#endif
    
  private:
    void start_ssl(rcComm_t& comm) {
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
irods::pam_interactive_authentication* plugin_factory(const std::string&, const std::string&) {
  return new irods::pam_interactive_authentication{};
}



#pragma once
#include "irods/private/pam/ipam_client.hpp"
#include <utility>
#include <condition_variable>
#include <thread>
#include <ctime>
#include <string>

namespace PamHandshake
{
  /**
   * PAM conversation session
   */
  class Session : public IPamClient
  {
  public:
    enum class State
      {
        Running,          // set by parent
        Ready,            // set by parent
        Waiting,          // set by worker
        WaitingPw,        // set by worker
        Response,         // set by parent when response is available
        Next,             // set by workder
        Error,            // set by parent
        Timeout,          // set by parent
        Authenticated,    // set by worker
        NotAuthenticated
      };
    // 0 -> Running               (parent)
    // Running -> Ready           (parent)
    // Ready -> Waiting           (worker)
    // Ready -> WaitingPw         (worker)
    // Ready -> Next              (worker)
    // Waiting -> Response        (parent)
    // WaitingPw -> Response      (parent)
    // Response -> Next           (worker)
    // Next -> Ready              (parent)
    // Ready -> Authenticated     (worker)
    // Ready -> NotAuthenticated  (worker)
    Session(const std::string & _pam_stack_name = "irods",
            const std::string & _conversation_program = "",
	    const std::string & _irods_username = "",
            bool _verbose = false);

    static std::shared_ptr<Session> getSingleton(const std::string & pam_stack_name="irods",
                                                 const std::string & conversation_program="",
						 const std::string & _irods_username = "",
                                                 std::size_t session_timeout=3600, // seconds
                                                 bool _verbose=false);

    static void resetSingleton();

    virtual ~Session();
    virtual void promptEchoOn(const char * msg, pam_response_t * resp) override;
    virtual void promptEchoOff(const char * msg, pam_response_t * resp) override;
    virtual void errorMsg(const char * msg) override;
    virtual void textInfo(const char * msg) override;
    virtual bool canceled() override;
    void cancel();
    inline static const char *  StateToString(const State & s);
    State getState() const;
    std::pair<State, std::string> pull(const char * response,
                                       std::size_t len);
    void refresh();
    std::time_t getLastTime() const;



  private:
    mutable std::mutex mutex;
    static std::shared_ptr<Session> singletonOp(bool create,
                                                const std::string & pam_stack_name,
                                                const std::string & conversation_program,
						const std::string & irods_username,
                                                std::size_t session_timeout, // seconds
                                                bool _verbose);

    std::string pam_stack_name;
    std::string conversation_program;
    std::string irods_username;
    bool verbose;
    std::pair<State, std::string> nextMessage;
    std::string nextResponse;
    std::condition_variable cv;
    std::time_t lastTime;
    std::thread t;

    void worker();
    inline void transition(State s, bool clean_string=true);
    inline bool statePredicate(State s);
  }; 

}

inline const char * PamHandshake::Session::StateToString(const Session::State & s)
{
  switch(s)
  {
  case State::Running: return "running";
  case State::Ready: return "ready";
  case State::Waiting: return "waiting";
  case State::WaitingPw: return "waiting_pw";
  case State::Response: return "response";
  case State::Next:  return "next";
  case State::Error:  return "error";
  case State::Timeout:  return "timeout";
  case State::Authenticated: return "authenticated";
  case State::NotAuthenticated: return "not_authenticated";
  }
}

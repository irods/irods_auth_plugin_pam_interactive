#include "irods/private/pam/handshake_session.hpp"
#include "irods/private/pam/auth_check_wrapper.hpp"
#include <functional>
#include <iostream>
#include <security/pam_appl.h>
#include <string.h>
#include <stdlib.h>

using namespace PamHandshake;

Session::Session(const std::string & _pam_stack_name,
                 const std::string & _conversation_program,
                 bool _verbose)
  : pam_stack_name(_pam_stack_name),
    conversation_program(_conversation_program),
    verbose(_verbose),
    nextMessage(std::make_pair(State::Running, "")),
    lastTime(std::time(nullptr)),
    t(std::bind(&Session::worker, this))
{
}

std::shared_ptr<Session> Session::singletonOp(bool create,
                                              const std::string & pam_stack_name,
                                              const std::string & conversation_program,
                                              std::size_t session_timeout, // seconds
                                              bool _verbose)
{
  static std::mutex gmutex;
  static std::shared_ptr<Session> instance;
  std::lock_guard<std::mutex> guard(gmutex);
  if(create)
  {
    if(!instance)
    {
      instance = std::make_shared<Session>(pam_stack_name,
                                           conversation_program,
                                           _verbose);
    }
  }
  else
  {
    instance.reset();
  }
  return instance;
}

std::shared_ptr<Session> Session::getSingleton(const std::string & pam_stack_name,
                                               const std::string & conversation_program,
                                               std::size_t session_timeout, // seconds
                                               bool _verbose)
{
  return Session::singletonOp(true,
                              pam_stack_name,
                              conversation_program,
                              session_timeout,
                              _verbose);
}

void Session::resetSingleton()
{
  Session::singletonOp(false, "", "", 0, false);
}


Session::~Session()
{
  t.join();
}

void Session::promptEchoOn(const char * msg, pam_response_t * resp)
{
  std::unique_lock<std::mutex> lk(mutex);
  if(verbose)
  {
    std::cout << "promptEchoOn \"" << msg << "\"" << std::endl;
    std::cout << "waiting for State::Ready" << std::endl;
  }
  cv.wait(lk, std::bind(&Session::statePredicate, this, State::Ready));
  if(nextMessage.first == State::Ready)
  {
    transition(State::Waiting);
    nextMessage.second = msg;

    lk.unlock();
    cv.notify_one();

    lk.lock();
    if(verbose)
    {
      std::cout << "waiting for State::Response" << std::endl;
    }

    cv.wait(lk, std::bind(&Session::statePredicate, this, State::Response));
    if(nextMessage.first == State::Response)
    {
      transition(State::Next);
      resp->resp = (char*)malloc(nextResponse.size() + 1);
      resp->resp = strdup(nextResponse.c_str());
      if(verbose)
      {
        std::cout << "resp: " << resp->resp << std::endl;
      }
      lk.unlock();
      cv.notify_one();
    }
  }
}

void Session::promptEchoOff(const char * msg, pam_response_t * resp)
{
  std::unique_lock<std::mutex> lk(mutex);
  if(verbose)
  {
    std::cout << "promptEchoOff \"" << msg << "\"" << std::endl;
    std::cout << "waiting for State::Ready" << std::endl;
  }
  cv.wait(lk, std::bind(&Session::statePredicate, this, State::Ready));
  if(nextMessage.first == State::Ready)
  {
    transition(State::WaitingPw);
    nextMessage.second = msg;
    lk.unlock();
    cv.notify_one();

    lk.lock();
    if(verbose)
    {
      std::cout << "waiting for State::Response" << std::endl;
    }
    cv.wait(lk, std::bind(&Session::statePredicate, this, State::Response));
    if(nextMessage.first == State::Response)
    {
      transition(State::Next);
      resp->resp = (char*)malloc(nextResponse.size() + 1);
      resp->resp = strdup(nextResponse.c_str());
      if(verbose)
      {
        std::cout << "resp: *****" << std::endl;
      }
      lk.unlock();
      cv.notify_one();
    }
  }
}

void Session::errorMsg(const char * msg)
{
  std::unique_lock<std::mutex> lk(mutex);
  if(verbose)
  {
    std::cout << "errorMsg \"" << msg << "\"" << std::endl;
    std::cout << "waiting for State::Ready" << std::endl;
  }
  cv.wait(lk, [this]{ return nextMessage.first == State::Ready;});
  if(nextMessage.first == State::Ready)
  {
    transition(State::Next);
    nextMessage.second = msg;
    lk.unlock();
    cv.notify_one();
  }
}

void Session::textInfo(const char * msg)
{
  std::unique_lock<std::mutex> lk(mutex);
  if(verbose)
  {
    std::cout << "textInfo " << msg << "\"" << std::endl;
    std::cout << "waiting for State::Ready" << std::endl;
  }
  cv.wait(lk, std::bind(&Session::statePredicate, this, State::Ready));
  if(nextMessage.first == State::Ready)
  {
    transition(State::Next);
    nextMessage.second = msg;
    lk.unlock();
    cv.notify_one();
  }
}

bool Session::canceled()
{
  std::lock_guard<std::mutex> lk(mutex);
  return (nextMessage.first == State::Timeout ||
          nextMessage.first == State::Error);
}

void Session::cancel()
{
  std::lock_guard<std::mutex> lk(mutex);
  lastTime = time(nullptr);
  nextMessage.first = State::Timeout;
}

void Session::refresh()
{
  std::lock_guard<std::mutex> lk(mutex);
  lastTime = time(nullptr);
}

std::time_t Session::getLastTime() const
{
  std::lock_guard<std::mutex> lk(mutex);
  return lastTime;
}

Session::State Session::getState() const
{
  std::lock_guard<std::mutex> lk(mutex);
  auto s = nextMessage.first;
  return s;
}

std::pair<Session::State, std::string> Session::pull(const char * response, std::size_t len)
{
  std::pair<State, std::string> ret;
  {
    std::lock_guard<std::mutex> lk(mutex);
    lastTime = time(nullptr);
    if(nextMessage.first > State::Next)
    {
      return nextMessage;
    }
    else if(nextMessage.first == State::Running ||
            nextMessage.first == State::Next)
    {
      transition(State::Ready);
    }
    else if(nextMessage.first == State::Waiting ||
            nextMessage.first == State::WaitingPw)
    {
      nextResponse = std::string(response, len);
      transition(State::Response);
    }
    else if(nextMessage.first == State::Ready)
    {
      // should not end here
      nextMessage.second = "Session::pull ivalid state: Ready";
      transition(State::Error);
    }
  }
  cv.notify_one();
  {
    std::unique_lock<std::mutex> lk(mutex);
    if(verbose)
    {
      std::cout << "waiting for State::Waiting || "
                << "State::WaitingPw || State::Next || >State::Next" << std::endl;
    }
    
    cv.wait(lk, [this]{ return nextMessage.first == State::Waiting ||
                               nextMessage.first == State::WaitingPw ||
                               nextMessage.first == State::Next ||
                               nextMessage.first >  State::Next; });
    ret = nextMessage;
  }
  return ret;
}

void Session::worker()
{
  bool result = false;
  bool err = false;
  std::string what;
  try
  {
    result = pam_auth_check_wrapper(conversation_program,
                                    pam_stack_name,
                                    *this,
                                    verbose);

  }
  catch(const std::exception & ex) 
  {
    what = std::string(ex.what());
    if(verbose)
    {
      std::cerr << what << std::endl;
    }
    err = true;
  }
  std::unique_lock<std::mutex> lk(mutex);
  cv.wait(lk, std::bind(&Session::statePredicate, this, State::Ready));
  if(nextMessage.first == State::Ready)
  {
    if(err)
    {
      transition(State::Error, false);
      nextMessage.second.append(what);
    }
    else if(result)
    {
      transition(State::Authenticated);
    }
    else
    {
      transition(State::NotAuthenticated);
    }
    lk.unlock();
    cv.notify_one();
  }
}

inline void Session::transition(State s, bool clean_str)
{
  if(verbose)
  {
    std::cout << "State " << Session::StateToString(nextMessage.first);
    nextMessage.first = s;
    std::cout << " --> " << Session::StateToString(nextMessage.first) << std::endl;
  }
  else
  {
    nextMessage.first = s;
  }
  if(clean_str)
  {
    nextMessage.second = "";
  }
}

inline bool Session::statePredicate(State s)
{
  return ( nextMessage.first == s ||
           nextMessage.first == State::Error ||
           nextMessage.first == State::Timeout );

}

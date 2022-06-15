#pragma once
#include <string>
#include <utility>
#include <security/pam_appl.h>
#include "ipam_client.hpp"
#include "pam_auth_check_exception.hpp"

namespace PamHandshake
{
  class PamAuthCheckException;

  int pam_conversation(int n,
                       const struct ::pam_message **msg,
                       struct ::pam_response **resp,
                       void *data);

  bool pam_auth_check(const std::string & pam_service,
                      IPamClient & client,
                      bool verbose);



  void pam_send_auth_result(bool result);
  void pam_send_exception(const PamAuthCheckException & ex);


  class PamBinClient : public IPamClient
  {
  public:
    virtual void promptEchoOn(const char * msg, pam_response_t * resp) override;
    virtual void promptEchoOff(const char * msg, pam_response_t * resp) override;
    virtual void errorMsg(const char * msg) override;
    virtual void textInfo(const char * msg) override;
    virtual bool canceled() override;
    static void writeMessage(int fd, int state, int type, const char * msg);
    static std::pair<int, int> readMessage(int fd, std::string & msg);
    static int readAnswerMessage(int fd, std::string & msg);
  };
}


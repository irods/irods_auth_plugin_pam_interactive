#pragma once
#include <stdexcept>
#include <string>

namespace PamHandshake
{
  class PamAuthCheckException : public std::runtime_error
  {
  public:
    PamAuthCheckException(int _pam_code,
                          std::string _msg) :
      std::runtime_error(_msg),
      msg(_msg),
      pam_code(_pam_code)
    {}

    int getPamCode() const {
      return pam_code;
    }

    std::string getMessage() const {
      return msg;
    }

    const char *what() const noexcept override {
      return "TestException";
    };
  private:
    std::string msg;
    int pam_code;
  };
}

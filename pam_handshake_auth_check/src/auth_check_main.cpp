/***********************************************************
 * 
 **/
#include "irods/private/pam/pam_conversation.hpp"
#include "irods/private/pam/auth_check_wrapper.hpp"
#include <string>
#include <exception>
#include <stdexcept>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <termios.h>

class PamClient : public ::PamHandshake::IPamClient
{
public:
  virtual void promptEchoOn(const char * msg, pam_response_t * resp) override
  {
    std::cout << "promptEchoOn \"" << msg << "\"" << std::endl;
    resp->resp_retcode = 0;
    std::size_t len = 0;
    resp->resp = NULL;
    if(getline(&resp->resp, &len, stdin) == -1)
    {
      throw ::std::runtime_error("failed to read message");
    }
    if(resp->resp)
    {
      resp->resp[strlen(resp->resp)-1] = '\0';
    }
  }

  virtual void promptEchoOff(const char * msg, pam_response_t * resp) override
  {
    std::cout << "promptEchoOff \"" << msg << "\"" << std::endl;
    resp->resp_retcode = 0;
    resp->resp = strdup(getpass(""));
  }

  virtual void errorMsg(const char * msg) override
  {
    std::cout << "errorMsg \"" << msg << "\"" << std::endl;
  }

  virtual void textInfo(const char * msg) override
  {
    std::cout << "textInfo \"" << msg << "\"" << std::endl;
  }

  virtual bool canceled() override
  {
    return false;
  }

};


/**
 * Parse a string value from argv[i]
 *
 * \param argc total number of arguments
 * \param const char ** argv argument values
 * \param int & i current possition. (the value is incremented by 1
 * \param bool & argError set to true if an error occurred
 * \return the value parsed from argv[i]
 */
static std::string parseString(int argc, const char ** argv, int & i, bool & argError)
{
  ++i;
  if(i < argc)
  {
    return std::string(argv[i]);
  }
  else
  {
    std::cerr << "missing argument " << argv[i-1] << " N" << std::endl;
    argError = true;
  }
  return std::string("");
}

#include <stdio.h>
/**
 * Execute PAM conversation on command line
 */
int main(int argc, const char ** argv)
{
  /* set default arguments */
  std::string pamStackName = "irods";
  std::string conversationProgram;
  bool printHelp = false;
  bool argError = false;
  bool verbose = false;
  bool bin = false;

  /* parse and validate arguments  */
  for(int i = 0; i < argc; ++i)
  {
    std::string arg(argv[i]);
    if(arg == "--stack")
    {
      pamStackName = parseString(argc, argv, i, argError);
    }
    else if(arg == "--conversation")
    {
      conversationProgram = parseString(argc, argv, i, argError);
    }
    else if(arg == "--bin")
    {
      bin = true;
    }
    else if(arg == "--help" || arg == "-h")
    {
      printHelp = true;
    }
    else if(arg == "--verbose" || arg == "-v")
    {
      verbose = true;
    }
  }
  if(printHelp || argError)
  {
    std::cout << argv[0] << "[OPTIONS]" << std::endl;
    std::cout << "OPTIONS:" << std::endl;
    std::cout << "--stack PAM_STACK_NAME" << std::endl;
    std::cout << "--conversation CONV_PROGRAM" << std::endl;
    std::cout << "--verbose|-v" << std::endl;
    std::cout << "--bin" << std::endl;
    std::cout << "--help|-h" << std::endl;
    if(argError)
    {
      return 1;
    }
    else
    {
      return 0;
    }
  }

  /* run PAM conversation  */
  bool result = false;
  if(conversationProgram.empty())
  {
    if(bin)
    {
      PamHandshake::PamBinClient client;
      try
      {
        result = PamHandshake::pam_auth_check(pamStackName, client, verbose);
        PamHandshake::pam_send_auth_result(result);
      }
      catch(PamHandshake::PamAuthCheckException ex)
      {
        PamHandshake::pam_send_exception(ex);
      }
    }
    else
    {
      PamClient client;
      result = ::PamHandshake::pam_auth_check(pamStackName, client, verbose);
    }
  }
  else
  {
    PamClient client;
    result = ::PamHandshake::pam_auth_check_wrapper(conversationProgram,
                                                    pamStackName,
                                                    client,
                                                    verbose);
  }
  if(result)
  {
    std::cout << "Authenticated" << std::endl;
  }
  else
  {
    std::cout << "Not Authenticated" << std::endl;
  }
  return 0;
}

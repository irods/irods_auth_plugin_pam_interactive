#pragma once
/**
 * IPamClient: interface to communication with PAM stack.
 * see https://linux.die.net/man/3/pam_conv
 *
 * Usage: derive a class and implement the PAM messages
 *        usa a instance as argument to the client argument in
 *        bool pam_auth_check(const std::string & pam_service,
 *                            IPamClient & client,
 *                            bool verbose);
 */
struct pam_response;

namespace PamHandshake
{
  class IPamClient
  {
  public:
    typedef struct ::pam_response pam_response_t;
    virtual ~IPamClient() {};

    /**
     * Obtain a string whilst echoing text.
     * \param msg
     * \param resp
     */
    virtual void promptEchoOn(const char * msg, pam_response_t * resp) = 0;

    /**
     * Obtain a string without echoing any text.
     *
     * \param msg
     * \param resp
     */
    virtual void promptEchoOff(const char * msg, pam_response_t * resp) = 0;

    /**
     * Display an error message.
     */
    virtual void errorMsg(const char * msg) = 0;

    /**
     * Display some text.
     */
    virtual void textInfo(const char * msg) = 0;

    virtual bool canceled() { return false; }
  };
}


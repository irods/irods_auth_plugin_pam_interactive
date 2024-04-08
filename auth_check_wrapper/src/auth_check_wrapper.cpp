#include "irods/private/pam/auth_check_wrapper.hpp"
#include "irods/private/pam/pam_auth_check_exception.hpp"
#include <cstdint>
#include <cstring>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#define MSG_PAM_CONV 1
#define MSG_PAM_RESPONSE 2
#define MSG_DONE 3
#define MSG_ERROR 4

static void writeMessage(int fd, int state, int type, const char * msg)
{
  unsigned char bytes[6];
  std::uint32_t n = static_cast<std::uint32_t>(std::strlen(msg));
  bytes[0] = state;
  bytes[1] = type;
  bytes[2] = n & 0xFF;
  bytes[3] = (n >> 8) & 0xFF;
  bytes[4] = (n >> 16) & 0xFF;
  bytes[5] = (n >> 24) & 0xFF;
  write(fd, bytes, sizeof(bytes));
  write(fd, msg, n);
}

static std::pair<int, int> readMessage(int fd, std::string & msg)
{
#define MESSAGE_SIZE 6
  // read header
  unsigned char bytes[MESSAGE_SIZE];
  std::size_t bytes_read;
  std::size_t pos = 0;
  int state = 0;
  int type = 0;
  std::size_t n = 0;
  std::size_t i;
  while(pos < MESSAGE_SIZE)
  {
    bytes_read = read(fd, bytes, MESSAGE_SIZE - pos);
    for(i = 0; i < bytes_read; i++)
    {
      if(pos == 0)
      {
        state = bytes[i];
      }
      else if(pos == 1)
      {
        type = bytes[i];
      }
      else
      {
        int c = bytes[i];
        int shiftby = (pos-2)*8;
        n+= (c << shiftby);
      }
      pos++;
    }
    if(!bytes_read)
    {
      break;
    }
  }
  if(pos < MESSAGE_SIZE)
  {
    return std::make_pair(0, 0);
  }
  std::size_t rem = n;
  char buffer[255];
  do
  {
    if(rem < sizeof(buffer))
    {
      bytes_read = read(fd, buffer, rem);
    }
    else
    {
      bytes_read = read(fd, buffer, sizeof(buffer));
    }
    rem-= bytes_read;
    msg.append(buffer, bytes_read);
  }
  while(bytes_read);
  return std::make_pair(state, type);
#undef MESSAGE_SIZE
}

bool PamHandshake::pam_auth_check_wrapper(const std::string & application,
					  const std::string & pam_service,
					  PamHandshake::IPamClient & client,
					  bool verbose,
					  const std::string & irods_username)
{
  int p_read[2];
  int p_write[2];
  if(pipe(p_read))
  {
    throw std::runtime_error("cannot create pipe");
  }
  if(pipe(p_write))
  {
    throw std::runtime_error("cannot create pipe");
  }
  pid_t child_pid = fork();
  if(child_pid < 0)
  {
    throw std::runtime_error("fork failed");
  }
  else if(child_pid == 0)
  {
    close(p_write[0]);
    close(p_read[1]);
    dup2(p_write[1], STDOUT_FILENO);
    dup2(p_read[0], STDIN_FILENO);
    execl(application.c_str(), "--bin", "--stack", pam_service.c_str(), "--username", irods_username.c_str(), nullptr);
    exit(0);
  }
  else
  {
    close(p_write[1]);
   close(p_read[0]);
    int fd_read = p_write[0];
    int fd_write = p_read[1];
    int ret = 0;
    while(true)
    {
      std::string msg;
      std::pair<int, int> code = readMessage(fd_read, msg);
      if(code.first == MSG_PAM_CONV)
      {
        if(code.second == PAM_PROMPT_ECHO_ON)
        {
          struct pam_response resp;
          client.promptEchoOn(msg.c_str(), &resp);
          writeMessage(fd_write, MSG_PAM_RESPONSE, 0, resp.resp);
        }
        else if(code.second == PAM_PROMPT_ECHO_OFF)
        {
          struct pam_response resp;
          client.promptEchoOff(msg.c_str(), &resp);
          writeMessage(fd_write, MSG_PAM_RESPONSE, 0, resp.resp);
        }
        else if(code.second == PAM_ERROR_MSG)
        {
          client.errorMsg(msg.c_str());
        }
        else if(code.second == PAM_TEXT_INFO)
        {
          client.textInfo(msg.c_str());
        }
        else
        {
          close(p_write[0]);
          close(p_read[1]);
          throw std::runtime_error(std::string(__FILE__) + std::string(":") +
                                   std::to_string(__LINE__)  + 
                                   std::string(" invalid PAM message type ") + std::to_string(code.second) +
                                   std::string(" executable: ") + application +
                                   std::string(" --bin --stack ") + pam_service);
        }
      }
      else if(code.first == MSG_DONE)
      {
        close(p_write[0]);
        close(p_read[1]);
        return (bool)code.second;
      }
      else if(code.first == MSG_ERROR)
      {
        close(p_write[0]);
        close(p_read[1]);
        throw PamAuthCheckException(code.second, msg.c_str());
      }
      else
      {
        close(p_write[0]);
        close(p_read[1]);
        throw std::runtime_error(std::string(__FILE__) + std::string(":") +
                                 std::to_string(__LINE__)  +
                                 std::string(" invalid status code ") + std::to_string(code.first) +
                                 std::string(" executable: ") + application +
                                 std::string(" --bin --stack ") + pam_service);
      }
    } // while true
    close(p_write[0]);
    close(p_read[1]);
    return ret;
  }
  return false;
}

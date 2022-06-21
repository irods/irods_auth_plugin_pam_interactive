#pragma once
/**

Operation types
=============
Input
-----
Read user input from promt

Parameters:
prompt:   message to be printed (optional, default "")
key:      user's response to be saved under this key (optional, default not set)
password: echo off when user enters response (otional, default false)
context:  "iinit"|"icommand"|"all" (optional default all)
expire:   "yyy-mm-dd hh:mm" (optional, when key is set, entry should expire by
                             this date)
{"op":       "input",
 "prompt":   "please enter something",
 "key":      "name", 
 "password": true,
 "context":  "all",
 "expire":   null}

Echo
----
print a message

Parameters:
prompt:   message to be printed
context: "iinit"|"icommand"|"all" (optional, default "all")

{"op":      "echo",
 "value":   "hello",
 "context": "iinit"}

Get
---
retrieve data from client

Parameters:
key:     key of the entry
Example:
{"op":  "get",
 "key": "name"}

Put
---
send data to client
Parameters:
key:      name of the key
value:    value
password: password
context:  "iinit"|"icommand"|"all" (optional, default "all")
expire:   "yyy-mm-dd hh:mm" (optional)

{"op":     "put",
 "key":    "name",
 "value":  "hello",
 "context": "iinit",
 "password": true,
 "expire":  "2022-05-12 12:00:00"
}

Delete
------
delete data on client

Parameters:
key:     "name"
context: "iinit"
 */
#include <nlohmann/json.hpp>
#include "handshake_session.hpp"
#include <ctime>
#include <iostream>
#include <sstream>
#include <locale>
#include <stdexcept>

namespace PamHandshake
{
  class Message
  {
  public:
    enum class Operation { Input, Echo, Get, Put, Delete };

    Message(Session::State state, const std::string & msg);
    ~Message();
    std::string update_json(nlohmann::json & j);
    
    Operation   op;
    bool        password;
    std::string prompt;
    std::string context;
    std::string key;
    std::string value;
    std::tm   * expire;
  private:
    void init_expire(const nlohmann::json & j);
  };


}

void PamHandshake::Message::init_expire(const nlohmann::json & j)
{
  if(j.contains("expire") && !j["expire"].is_null())
  {
    std::istringstream ss(j.value("expire", std::string("")));
    std::tm t = {};
    ss.imbue(std::locale("en_us.utf-8"));
    ss >> std::get_time(&t, "%Y-%m-%d %H:%M:%S");
    if (ss.fail())
    {
      throw std::runtime_error(std::string("failed to parse date time:'") +
                               j.value("expire", std::string("") + "'"));
    }
    expire = new std::tm(t);
  }
  else
  {
    expire = nullptr;
  }
}

PamHandshake::Message::Message(Session::State state, const std::string & msg)
{
  expire = nullptr;
  if(state == Session::State::Waiting ||
     state == Session::State::WaitingPw)
  {
    if(msg.empty() || msg[0] != '{')
    {
      op = Operation::Input;
      password = (state == Session::State::WaitingPw);
      prompt = msg;
    }
    else
    {
      op = Operation::Input;
      nlohmann::json j = nlohmann::json::parse(msg, nullptr, true);
      prompt = j.value("prompt", std::string(""));
      key = j.value("key", std::string(""));
      password = j.value("password", (state == Session::State::WaitingPw));
      context = j.value("context", "all");
      init_expire(j);
    }
  }
  else
  {
    op = Operation::Echo;
    if(msg.empty() || msg[0] != '{')
    {
      password = false;
      prompt = msg;
    }
    else
    {
      nlohmann::json j = nlohmann::json::parse(msg, nullptr, true);
      std::string opstr = j.value("op", std::string("echo"));
      if(opstr == "get")
      {
        op = Operation::Get;
      }
      else if(opstr == "put")
      {
        op = Operation::Put;
      }
      else if(opstr == "delete")
      {
        op = Operation::Delete;
      }
      prompt = j.value("prompt", std::string(""));
      value = j.value("value", std::string(""));
      key = j.value("key", std::string(""));
      password = j.value("password", (state == Session::State::WaitingPw));
      context = j.value("context", "all");
      init_expire(j);
    }
  }
}

PamHandshake::Message::~Message()
{
  if(expire)
  {
    delete expire;
  }
}

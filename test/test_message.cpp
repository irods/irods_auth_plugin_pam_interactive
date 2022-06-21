#include <catch2/catch.hpp>
#include "pam_message.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <iostream>
#include <sstream>
#include <locale>
#include <stdexcept>

using Message = PamHandshake::Message;
using Session = PamHandshake::Session;

TEST_CASE("waiting_standard_message", "[Message]")
{
  Message msg(Session::State::Waiting, "abc");
  REQUIRE_FALSE(msg.password);
  REQUIRE(msg.op == Message::Operation::Input);
  REQUIRE(msg.prompt == "abc");
}

TEST_CASE("waiting_json_invalid_message", "[Message]")
{
  REQUIRE_THROWS(Message(Session::State::Waiting, "{\"abc\":"));
}

TEST_CASE("waiting_json_message", "[Message]")
{
  Message msg(Session::State::Waiting, R"({
    "prompt":   "please enter something",
    "key":      "name", 
    "password": true,
    "context":  "all",
    "expire":   "2022-05-20 23:23:12"}
  )");
  std::istringstream ss("2022-05-21 00:00:00");
  std::tm t = {};
  ss.imbue(std::locale("en_us.utf-8"));
  ss >> std::get_time(&t, "%Y-%m-%d %H:%M:%S");
  REQUIRE(msg.op == Message::Operation::Input);
  REQUIRE(std::difftime(std::mktime(&t), std::mktime(msg.expire)) > 0);
}

TEST_CASE("waiting_pw_standard_message", "[Message]")
{
  Message msg(Session::State::WaitingPw, "abc");
  REQUIRE(msg.op == Message::Operation::Input);
  REQUIRE(msg.password);
  REQUIRE(msg.prompt == "abc");
}

TEST_CASE("put_operation", "[Message]")
{
  Message msg(Session::State::Next, R"({
    "op":       "put",
    "value":    "value",
    "key":      "name", 
    "password": true,
    "context":  "all",
    "expire":   "2022-05-20 23:23:12"}
  )");
  std::istringstream ss("2022-05-21 00:00:00");
  std::tm t = {};
  ss.imbue(std::locale("en_us.utf-8"));
  ss >> std::get_time(&t, "%Y-%m-%d %H:%M:%S");
  REQUIRE(msg.op == Message::Operation::Put);
  REQUIRE(msg.password);
  REQUIRE(msg.key == "name");
  REQUIRE(msg.value == "value");
  REQUIRE(msg.context == "all");
  REQUIRE(std::difftime(std::mktime(&t), std::mktime(msg.expire)) > 0);
}


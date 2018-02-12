// Copyright (c) 2018, Logicoin

#pragma once

#include <condition_variable>
#include <mutex>
#include <stdint.h>

namespace CryptoNote {

class WalletAsyncContextCounter
{
public:
  WalletAsyncContextCounter() : m_asyncContexts(0) {}

  void addAsyncContext();
  void delAsyncContext();

  //returns true if contexts are finished before timeout
  void waitAsyncContextsFinish();

private:
  uint32_t m_asyncContexts;
  std::condition_variable m_cv;
  std::mutex m_mutex;
};

} //namespace CryptoNote

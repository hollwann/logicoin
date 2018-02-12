// Copyright (c) 2018, Logicoin

#include "WalletAsyncContextCounter.h"

namespace CryptoNote {

void WalletAsyncContextCounter::addAsyncContext() {
  std::unique_lock<std::mutex> lock(m_mutex);
  m_asyncContexts++;
}

void WalletAsyncContextCounter::delAsyncContext() {
  std::unique_lock<std::mutex> lock(m_mutex);
  m_asyncContexts--;

  if (!m_asyncContexts) m_cv.notify_one();
}

void WalletAsyncContextCounter::waitAsyncContextsFinish() {
  std::unique_lock<std::mutex> lock(m_mutex);
  while (m_asyncContexts > 0)
    m_cv.wait(lock);
}

} //namespace CryptoNote

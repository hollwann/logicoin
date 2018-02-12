// Copyright (c) 2018, Logicoin

#pragma once 

#include <functional>

namespace Tools {

class ScopeExit {
public:
  ScopeExit(std::function<void()>&& handler);
  ~ScopeExit();

  ScopeExit(const ScopeExit&) = delete;
  ScopeExit(ScopeExit&&) = delete;
  ScopeExit& operator=(const ScopeExit&) = delete;
  ScopeExit& operator=(ScopeExit&&) = delete;

  void cancel();

private:
  std::function<void()> m_handler;
  bool m_cancelled;
};

}

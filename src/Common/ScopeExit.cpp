// Copyright (c) 2018, Logicoin

#include "ScopeExit.h"

namespace Tools {

ScopeExit::ScopeExit(std::function<void()>&& handler) :
  m_handler(std::move(handler)),
  m_cancelled(false) {
}

ScopeExit::~ScopeExit() {
  if (!m_cancelled) {
    m_handler();
  }
}

void ScopeExit::cancel() {
  m_cancelled = true;
}

}

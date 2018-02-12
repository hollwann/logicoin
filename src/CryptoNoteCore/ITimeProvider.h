// Copyright (c) 2018, Logicoin

#pragma once

#include <time.h>

namespace CryptoNote {

  struct ITimeProvider {
    virtual time_t now() = 0;
    virtual ~ITimeProvider() {}
  };

  struct RealTimeProvider : public ITimeProvider {
    virtual time_t now() override {
      return time(nullptr);
    }
  };

}

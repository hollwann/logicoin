// Copyright (c) 2018, Logicoin

#pragma once

namespace CryptoNote {
class ITxPoolObserver {
public:
  virtual ~ITxPoolObserver() {
  }

  virtual void txDeletedFromPool() = 0;
};
}

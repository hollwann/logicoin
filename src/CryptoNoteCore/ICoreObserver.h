// Copyright (c) 2018, Logicoin

#pragma once

namespace CryptoNote {

class ICoreObserver {
public:
  virtual ~ICoreObserver() {};
  virtual void blockchainUpdated() {};
  virtual void poolUpdated() {};
};

}

// Copyright (c) 2018, Logicoin

#pragma once

namespace CryptoNote {
  class IBlockchainStorageObserver {
  public:
    virtual ~IBlockchainStorageObserver() {
    }

    virtual void blockchainUpdated() = 0;
  };
}

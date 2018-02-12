// Copyright (c) 2018, Logicoin

#pragma once

#include "CryptoNote.h"

namespace CryptoNote {
class IBlock {
public:
  virtual ~IBlock();

  virtual const Block& getBlock() const = 0;
  virtual size_t getTransactionCount() const = 0;
  virtual const Transaction& getTransaction(size_t index) const = 0;
};
}

// Copyright (c) 2018, Logicoin

#pragma once

#include <array>
#include <memory>
#include <cstdint>

#include <boost/optional.hpp>

#include "INode.h"
#include "ITransaction.h"

namespace CryptoNote {

struct BlockchainInterval {
  uint32_t startHeight;
  std::vector<Crypto::Hash> blocks;
};

struct CompleteBlock {
  Crypto::Hash blockHash;
  boost::optional<CryptoNote::Block> block;
  // first transaction is always coinbase
  std::list<std::shared_ptr<ITransactionReader>> transactions;
};

}

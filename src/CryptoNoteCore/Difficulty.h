// Copyright (c) 2018, Logicoin

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.h"

namespace CryptoNote
{
    typedef std::uint64_t difficulty_type;

    bool check_hash(const Crypto::Hash &hash, difficulty_type difficulty);
}

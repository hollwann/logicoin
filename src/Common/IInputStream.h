// Copyright (c) 2018, Logicoin

#pragma once

#include <cstddef>

namespace Common {

class IInputStream {
public:
  virtual ~IInputStream() { }
  virtual size_t readSome(void* data, size_t size) = 0;
};

}

// Copyright (c) 2018, Logicoin

#pragma once

#include <istream>
#include "IInputStream.h"

namespace Common {

class StdInputStream : public IInputStream {
public:
  StdInputStream(std::istream& in);
  StdInputStream& operator=(const StdInputStream&) = delete;
  size_t readSome(void* data, size_t size) override;

private:
  std::istream& in;
};

}

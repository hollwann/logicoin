// Copyright (c) 2018, Logicoin

#include "MemoryInputStream.h"
#include <algorithm>
#include <cassert>
#include <cstring> // memcpy

namespace Common {

MemoryInputStream::MemoryInputStream(const void* buffer, size_t bufferSize) : 
buffer(static_cast<const char*>(buffer)), bufferSize(bufferSize), position(0) {}

size_t MemoryInputStream::getPosition() const {
  return position;
}

bool MemoryInputStream::endOfStream() const {
  return position == bufferSize;
}

size_t MemoryInputStream::readSome(void* data, size_t size) {
  assert(position <= bufferSize);
  size_t readSize = std::min(size, bufferSize - position);

  if (readSize > 0) {
    memcpy(data, buffer + position, readSize);
    position += readSize;
  }
  
  return readSize;
}

}

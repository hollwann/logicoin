// Copyright (c) 2018, Logicoin

#pragma once

#include <fstream>
#include "StreamLogger.h"

namespace Logging {

class FileLogger : public StreamLogger {
public:
  FileLogger(Level level = DEBUGGING);
  void init(const std::string& filename);

private:
  std::ofstream fileStream;
};

}

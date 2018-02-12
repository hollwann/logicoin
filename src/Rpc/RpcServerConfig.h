// Copyright (c) 2018, Logicoin

#pragma once

#include <boost/program_options.hpp>

namespace CryptoNote {

class RpcServerConfig {
public:

  RpcServerConfig();

  static void initOptions(boost::program_options::options_description& desc);
  void init(const boost::program_options::variables_map& options);

  std::string getBindAddress() const;

  std::string bindIp;
  uint16_t bindPort;
};

}

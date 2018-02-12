// Copyright (c) 2018, Logicoin

#pragma once

#include <string>

#include <boost/program_options.hpp>

namespace CryptoNote {

class CoreConfig {
public:
  CoreConfig();

  static void initOptions(boost::program_options::options_description& desc);
  void init(const boost::program_options::variables_map& options);

  std::string configFolder;
  bool configFolderDefaulted = true;
};

} //namespace CryptoNote

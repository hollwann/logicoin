// Copyright (c) 2018, Logicoin

#include "CoreConfig.h"

#include "Common/Util.h"
#include "Common/CommandLine.h"

namespace CryptoNote {

CoreConfig::CoreConfig() {
  configFolder = Tools::getDefaultDataDirectory();
}

void CoreConfig::init(const boost::program_options::variables_map& options) {
  if (options.count(command_line::arg_data_dir.name) != 0 && (!options[command_line::arg_data_dir.name].defaulted() || configFolder == Tools::getDefaultDataDirectory())) {
    configFolder = command_line::get_arg(options, command_line::arg_data_dir);
    configFolderDefaulted = options[command_line::arg_data_dir.name].defaulted();
  }
}

void CoreConfig::initOptions(boost::program_options::options_description& desc) {
}
} //namespace CryptoNote

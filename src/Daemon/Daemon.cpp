// Copyright (c) 2018, Logicoin

#include "version.h"

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "DaemonCommandsHandler.h"

#include "Common/SignalHandler.h"
#include "Common/PathTools.h"
#include "crypto/hash.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "P2p/NetNode.h"
#include "P2p/NetNodeConfig.h"
#include "Rpc/RpcServer.h"
#include "Rpc/RpcServerConfig.h"
#include "version.h"

#include <Logging/LoggerManager.h>

#if defined(WIN32)
#include <crtdbg.h>
#endif

using Common::JsonValue;
using namespace CryptoNote;
using namespace Logging;

namespace po = boost::program_options;

namespace
{
  const command_line::arg_descriptor<std::string> arg_config_file = {"config-file", "Especifica archivo de configuracion", std::string(CryptoNote::CRYPTONOTE_NAME) + ".conf"};
  const command_line::arg_descriptor<bool>        arg_os_version  = {"os-version", ""};
  const command_line::arg_descriptor<std::string> arg_log_file    = {"log-file", "", ""};
  const command_line::arg_descriptor<int>         arg_log_level   = {"log-level", "", 2}; // info level
  const command_line::arg_descriptor<bool>        arg_console     = {"no-console", "Deshabilitar comandos de la consola daemon"};
  const command_line::arg_descriptor<bool>        arg_restricted_rpc = {"restricted-rpc", "Restringir RPC para ver solo comandos, para evitar el abuso"};
  const command_line::arg_descriptor<bool>        arg_enable_blockchain_indexes = { "enable-blockchain-indexes", "Habilitar indices blockchain", false };
  const command_line::arg_descriptor<bool>        arg_print_genesis_tx = { "print-genesis-tx", "Imprime el bloque de genesis tx hex para insertarlo en la configuracion y las salidas" };
  const command_line::arg_descriptor<std::string> arg_enable_cors = { "enable-cors", "Agrega el encabezado 'Access-Control-Allow-Origin' a las respuestas RPC del daemon. Utiliza el valor como dominio. Use * para todos", "" };
  const command_line::arg_descriptor<std::string> arg_set_fee_address = { "fee-address", "Establece la direccion de la tarifa para billeteras livianas a las respuestas RPC del daemon", "" };
  const command_line::arg_descriptor<bool>        arg_testnet_on  = {"testnet", "Se usa para implementar redes de prueba. Se ignoran los puntos de control y las semillas codificadas, "
    "la identificacion de la red ha cambiado. uselo con la bandera --data-dir. La billetera debe ser lanzada con --testnet flag.", false};
}

bool command_line_preprocessor(const boost::program_options::variables_map& vm, LoggerRef& logger);
void print_genesis_tx_hex(const po::variables_map& vm, LoggerManager& logManager) {
  CryptoNote::Transaction tx = CryptoNote::CurrencyBuilder(logManager).generateGenesisTransaction();
  std::string tx_hex = Common::toHex(CryptoNote::toBinaryArray(tx));
  std::cout << "Agregue esta linea en su archivo de configuracion de monedas como esta: " << std::endl;
  std::cout << "\"GENESIS_COINBASE_TX_HEX\":\"" << tx_hex << "\"," << std::endl;
  return;
}

JsonValue buildLoggerConfiguration(Level level, const std::string& logfile) {
  JsonValue loggerConfiguration(JsonValue::OBJECT);
  loggerConfiguration.insert("globalLevel", static_cast<int64_t>(level));

  JsonValue& cfgLoggers = loggerConfiguration.insert("loggers", JsonValue::ARRAY);

  JsonValue& fileLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  fileLogger.insert("type", "file");
  fileLogger.insert("filename", logfile);
  fileLogger.insert("level", static_cast<int64_t>(TRACE));

  JsonValue& consoleLogger = cfgLoggers.pushBack(JsonValue::OBJECT);
  consoleLogger.insert("type", "console");
  consoleLogger.insert("level", static_cast<int64_t>(TRACE));
  consoleLogger.insert("pattern", "%D %T %L ");

  return loggerConfiguration;
}


int main(int argc, char* argv[])
{

#ifdef WIN32
  _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif

  LoggerManager logManager;
  LoggerRef logger(logManager, "daemon");

  try {

    po::options_description desc_cmd_only("Opciones de linea de comando");
    po::options_description desc_cmd_sett("Opciones de linea de comando y opciones de configuracion");

    command_line::add_arg(desc_cmd_only, command_line::arg_help);
    command_line::add_arg(desc_cmd_only, command_line::arg_version);
    command_line::add_arg(desc_cmd_only, arg_os_version);
    // tools::get_default_data_dir() can't be called during static initialization
    command_line::add_arg(desc_cmd_only, command_line::arg_data_dir, Tools::getDefaultDataDirectory());
    command_line::add_arg(desc_cmd_only, arg_config_file);

    command_line::add_arg(desc_cmd_sett, arg_log_file);
    command_line::add_arg(desc_cmd_sett, arg_log_level);
    command_line::add_arg(desc_cmd_sett, arg_console);
	command_line::add_arg(desc_cmd_sett, arg_restricted_rpc);
    command_line::add_arg(desc_cmd_sett, arg_testnet_on);
	command_line::add_arg(desc_cmd_sett, arg_enable_cors);
	command_line::add_arg(desc_cmd_sett, arg_set_fee_address);
	command_line::add_arg(desc_cmd_sett, arg_enable_blockchain_indexes);
	command_line::add_arg(desc_cmd_sett, arg_print_genesis_tx);

    RpcServerConfig::initOptions(desc_cmd_sett);
    CoreConfig::initOptions(desc_cmd_sett);
    NetNodeConfig::initOptions(desc_cmd_sett);
    MinerConfig::initOptions(desc_cmd_sett);

    po::options_description desc_options("Opciones permitidas");
    desc_options.add(desc_cmd_only).add(desc_cmd_sett);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc_options, [&]()
    {
      po::store(po::parse_command_line(argc, argv, desc_options), vm);

      if (command_line::get_arg(vm, command_line::arg_help))
      {
        std::cout << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG << ENDL << ENDL;
        std::cout << desc_options << std::endl;
        return false;
      }

      std::string data_dir = command_line::get_arg(vm, command_line::arg_data_dir);
      std::string config = command_line::get_arg(vm, arg_config_file);

      boost::filesystem::path data_dir_path(data_dir);
      boost::filesystem::path config_path(config);
      if (!config_path.has_parent_path()) {
        config_path = data_dir_path / config_path;
      }

      boost::system::error_code ec;
      if (boost::filesystem::exists(config_path, ec)) {
        po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), desc_cmd_sett), vm);
      }
      po::notify(vm);
      if (command_line::get_arg(vm, arg_print_genesis_tx)) {
        print_genesis_tx_hex(vm, logManager);
        return false;
      }
      return true;
    });

    if (!r)
      return 1;
  
    auto modulePath = Common::NativePathToGeneric(argv[0]);
    auto cfgLogFile = Common::NativePathToGeneric(command_line::get_arg(vm, arg_log_file));

    if (cfgLogFile.empty()) {
      cfgLogFile = Common::ReplaceExtenstion(modulePath, ".log");
    } else {
      if (!Common::HasParentPath(cfgLogFile)) {
        cfgLogFile = Common::CombinePath(Common::GetPathDirectory(modulePath), cfgLogFile);
      }
    }

    Level cfgLogLevel = static_cast<Level>(static_cast<int>(Logging::ERROR) + command_line::get_arg(vm, arg_log_level));

    // configure logging
    logManager.configure(buildLoggerConfiguration(cfgLogLevel, cfgLogFile));

    logger(INFO) << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG;

    if (command_line_preprocessor(vm, logger)) {
      return 0;
    }

    logger(INFO) << "Carpeta del modulo: " << argv[0];

    bool testnet_mode = command_line::get_arg(vm, arg_testnet_on);
    if (testnet_mode) {
      logger(INFO) << "Comenzando en el modo testnet!";
    }

    //crear objetos y vincularlos
    CryptoNote::CurrencyBuilder currencyBuilder(logManager);
    currencyBuilder.testnet(testnet_mode);
    try {
      currencyBuilder.currency();
    } catch (std::exception&) {
      std::cout << "GENESIS_COINBASE_TX_HEX la constante tiene un valor incorrecto. Por favor inicie: " << CryptoNote::CRYPTONOTE_NAME << "d --" << arg_print_genesis_tx.name;
      return 1;
    }
    CryptoNote::Currency currency = currencyBuilder.currency();
    CryptoNote::core ccore(currency, nullptr, logManager, command_line::get_arg(vm, arg_enable_blockchain_indexes));

    CryptoNote::Checkpoints checkpoints(logManager);
    for (const auto& cp : CryptoNote::CHECKPOINTS) {
      checkpoints.add_checkpoint(cp.height, cp.blockId);
    }

    if (!testnet_mode) {
      ccore.set_checkpoints(std::move(checkpoints));
    }

    CoreConfig coreConfig;
    coreConfig.init(vm);
    NetNodeConfig netNodeConfig;
    netNodeConfig.init(vm);
    netNodeConfig.setTestnet(testnet_mode);
    MinerConfig minerConfig;
    minerConfig.init(vm);
    RpcServerConfig rpcConfig;
    rpcConfig.init(vm);

    if (!coreConfig.configFolderDefaulted) {
      if (!Tools::directoryExists(coreConfig.configFolder)) {
        throw std::runtime_error("El directorio no existe: " + coreConfig.configFolder);
      }
    } else {
      if (!Tools::create_directories_if_necessary(coreConfig.configFolder)) {
        throw std::runtime_error("No se puede crear el directorio: " + coreConfig.configFolder);
      }
    }

    System::Dispatcher dispatcher;

    CryptoNote::CryptoNoteProtocolHandler cprotocol(currency, dispatcher, ccore, nullptr, logManager);
    CryptoNote::NodeServer p2psrv(dispatcher, cprotocol, logManager);
    CryptoNote::RpcServer rpcServer(dispatcher, logManager, ccore, p2psrv, cprotocol);

    cprotocol.set_p2p_endpoint(&p2psrv);
    ccore.set_cryptonote_protocol(&cprotocol);
    DaemonCommandsHandler dch(ccore, p2psrv, logManager);

    // initialize objects
    logger(INFO) << "Inicializando el servidor p2p...";
    if (!p2psrv.init(netNodeConfig)) {
      logger(ERROR, BRIGHT_RED) << "Error al inicializar el servidor p2p.";
      return 1;
    }
    logger(INFO) << "Servidor P2P inicializado OK";

    //logger(INFO) << "Initializing core rpc server...";
    //if (!rpc_server.init(vm)) {
    //  logger(ERROR, BRIGHT_RED) << "Failed to initialize core rpc server.";
    //  return 1;
    //}
    // logger(INFO, BRIGHT_GREEN) << "Core rpc server initialized OK on port: " << rpc_server.get_binded_port();

    // initialize core here
    logger(INFO) << "Inicializando el nucleo...";
    if (!ccore.init(coreConfig, minerConfig, true)) {
      logger(ERROR, BRIGHT_RED) << "Error al inicializar el nucleo";
      return 1;
    }
    logger(INFO) << "Nucleo inicializado OK";

    // start components
    if (!command_line::has_arg(vm, arg_console)) {
      dch.start_handling();
    }

    logger(INFO) << "Iniciando el servidor core rpc en la direccion " << rpcConfig.getBindAddress();
    rpcServer.start(rpcConfig.bindIp, rpcConfig.bindPort);
	rpcServer.restrictRPC(command_line::get_arg(vm, arg_restricted_rpc));
	rpcServer.enableCors(command_line::get_arg(vm, arg_enable_cors));
	rpcServer.setFeeAddress(command_line::get_arg(vm, arg_set_fee_address));
    logger(INFO) << "El servidor Core rpc comenzo ok";

    Tools::SignalHandler::install([&dch, &p2psrv] {
      dch.stop_handling();
      p2psrv.sendStopSignal();
    });

    logger(INFO) << "Iniciando p2p net loop...";
    p2psrv.run();
    logger(INFO) << "p2p net loop detenido";

    dch.stop_handling();

    //stop components
    logger(INFO) << "Deteniendo servidor core rpc...";
    rpcServer.stop();

    //deinitialize components
    logger(INFO) << "Desinicializando nucleo...";
    ccore.deinit();
    logger(INFO) << "Desinicializando p2p...";
    p2psrv.deinit();

    ccore.set_cryptonote_protocol(NULL);
    cprotocol.set_p2p_endpoint(NULL);

  } catch (const std::exception& e) {
    logger(ERROR, BRIGHT_RED) << "Excepcion: " << e.what();
    return 1;
  }

  logger(INFO) << "El nodo se detuvo.";
  return 0;
}

bool command_line_preprocessor(const boost::program_options::variables_map &vm, LoggerRef &logger) {
  bool exit = false;

  if (command_line::get_arg(vm, command_line::arg_version)) {
    std::cout << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG << ENDL;
    exit = true;
  }
  if (command_line::get_arg(vm, arg_os_version)) {
    std::cout << "OS: " << Tools::get_os_version_string() << ENDL;
    exit = true;
  }

  if (exit) {
    return true;
  }

  return false;
}

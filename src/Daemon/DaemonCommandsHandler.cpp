// Copyright (c) 2018, Logicoin

#include "DaemonCommandsHandler.h"

#include "P2p/NetNode.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "Serialization/SerializationTools.h"
#include "version.h"

namespace {
  template <typename T>
  static bool print_as_json(const T& obj) {
    std::cout << CryptoNote::storeToJson(obj) << ENDL;
    return true;
  }
}


DaemonCommandsHandler::DaemonCommandsHandler(CryptoNote::core& core, CryptoNote::NodeServer& srv, Logging::LoggerManager& log) :
  m_core(core), m_srv(srv), logger(log, "daemon"), m_logManager(log) {
  m_consoleHandler.setHandler("exit", boost::bind(&DaemonCommandsHandler::exit, this, _1), "Apagar el daemon");
  m_consoleHandler.setHandler("help", boost::bind(&DaemonCommandsHandler::help, this, _1), "Muestra esta ayuda");
  m_consoleHandler.setHandler("print_pl", boost::bind(&DaemonCommandsHandler::print_pl, this, _1), "Imprimir lista de pares");
  m_consoleHandler.setHandler("print_cn", boost::bind(&DaemonCommandsHandler::print_cn, this, _1), "Imprimir conexiones");
  m_consoleHandler.setHandler("print_bc", boost::bind(&DaemonCommandsHandler::print_bc, this, _1), "Imprimir informacion de blockchain en un rango de bloques dado, print_bc <inicio> [<fin>]");
  //m_consoleHandler.setHandler("print_bci", boost::bind(&DaemonCommandsHandler::print_bci, this, _1));
  //m_consoleHandler.setHandler("print_bc_outs", boost::bind(&DaemonCommandsHandler::print_bc_outs, this, _1));
  m_consoleHandler.setHandler("print_block", boost::bind(&DaemonCommandsHandler::print_block, this, _1), "Imprimir bloque, print_block <block_hash> | <block_height>");
  m_consoleHandler.setHandler("print_tx", boost::bind(&DaemonCommandsHandler::print_tx, this, _1), "Imprimir transaccion, print_tx <transaction_hash>");
  m_consoleHandler.setHandler("start_mining", boost::bind(&DaemonCommandsHandler::start_mining, this, _1), "Comience a minar para la direccion especificada, start_mining <addr> [threads=1]");
  m_consoleHandler.setHandler("stop_mining", boost::bind(&DaemonCommandsHandler::stop_mining, this, _1), "Deja de minar");
  m_consoleHandler.setHandler("print_pool", boost::bind(&DaemonCommandsHandler::print_pool, this, _1), "Imprimir grupo de transacciones (formato largo)");
  m_consoleHandler.setHandler("print_pool_sh", boost::bind(&DaemonCommandsHandler::print_pool_sh, this, _1), "Imprimir grupo de transacciones (formato corto)");
  m_consoleHandler.setHandler("show_hr", boost::bind(&DaemonCommandsHandler::show_hr, this, _1), "Comience a mostrar la tasa de hash");
  m_consoleHandler.setHandler("hide_hr", boost::bind(&DaemonCommandsHandler::hide_hr, this, _1), "Dejar de mostrar la tasa de hash");
  m_consoleHandler.setHandler("set_log", boost::bind(&DaemonCommandsHandler::set_log, this, _1), "set_log <level> - Cambiar el nivel de registro actual, <level> es un numero entre 0-4");
}

//--------------------------------------------------------------------------------
std::string DaemonCommandsHandler::get_commands_str()
{
  std::stringstream ss;
  ss << CryptoNote::CRYPTONOTE_NAME << " v" << PROJECT_VERSION_LONG << ENDL;
  ss << "Comandos: " << ENDL;
  std::string usage = m_consoleHandler.getUsage();
  boost::replace_all(usage, "\n", "\n  ");
  usage.insert(0, "  ");
  ss << usage << ENDL;
  return ss.str();
}

//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::exit(const std::vector<std::string>& args) {
  m_consoleHandler.requestStop();
  m_srv.sendStopSignal();
  return true;
}

//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::help(const std::vector<std::string>& args) {
  std::cout << get_commands_str() << ENDL;
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_pl(const std::vector<std::string>& args) {
  m_srv.log_peerlist();
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::show_hr(const std::vector<std::string>& args)
{
  if (!m_core.get_miner().is_mining())
  {
    std::cout << "La mineria no ha comenzado. Debe comenzar a minar antes de poder ver la tasa de hash." << ENDL;
  } else
  {
    m_core.get_miner().do_print_hashrate(true);
  }
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::hide_hr(const std::vector<std::string>& args)
{
  m_core.get_miner().do_print_hashrate(false);
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_bc_outs(const std::vector<std::string>& args)
{
  if (args.size() != 1)
  {
    std::cout << "necesita la ruta del archivo como parametro" << ENDL;
    return true;
  }
  m_core.print_blockchain_outs(args[0]);
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_cn(const std::vector<std::string>& args)
{
  m_srv.get_payload_object().log_connections();
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_bc(const std::vector<std::string> &args) {
  if (!args.size()) {
    std::cout << "necesita parametro de indice de bloque" << ENDL;
    return false;
  }

  uint32_t start_index = 0;
  uint32_t end_index = 0;
  uint32_t end_block_parametr = m_core.get_current_blockchain_height();
  if (!Common::fromString(args[0], start_index)) {
    std::cout << "parametro de indice de bloqueo de arranque incorrecto" << ENDL;
    return false;
  }

  if (args.size() > 1 && !Common::fromString(args[1], end_index)) {
    std::cout << "parametro de indice de bloque final erroneo" << ENDL;
    return false;
  }

  if (end_index == 0) {
    end_index = end_block_parametr;
  }

  if (end_index > end_block_parametr) {
    std::cout << "parametro de indice de bloque final no debe ser mayor que " << end_block_parametr << ENDL;
    return false;
  }

  if (end_index <= start_index) {
    std::cout << "el indice del bloque final debe ser mayor que el indice del bloque de inicio" << ENDL;
    return false;
  }

  m_core.print_blockchain(start_index, end_index);
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_bci(const std::vector<std::string>& args)
{
  m_core.print_blockchain_index();
  return true;
}

bool DaemonCommandsHandler::set_log(const std::vector<std::string>& args)
{
  if (args.size() != 1) {
    std::cout << "uso: set_log <log_level_number_0-5>" << ENDL;
    return true;
  }

  uint16_t l = 0;
  if (!Common::fromString(args[0], l)) {
    std::cout << "formato de numero equivocado, usa: set_log <log_level_number_0-4>" << ENDL;
    return true;
  }

  ++l;

  if (l > Logging::TRACE) {
    std::cout << "rango de numeros incorrectos, usa: set_log <log_level_number_0-4>" << ENDL;
    return true;
  }

  m_logManager.setMaxLevel(static_cast<Logging::Level>(l));
  return true;
}

//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_block_by_height(uint32_t height)
{
  std::list<CryptoNote::Block> blocks;
  m_core.get_blocks(height, 1, blocks);

  if (1 == blocks.size()) {
    std::cout << "block_id: " << get_block_hash(blocks.front()) << ENDL;
    print_as_json(blocks.front());
  } else {
    uint32_t current_height;
    Crypto::Hash top_id;
    m_core.get_blockchain_top(current_height, top_id);
    std::cout << "bloque no fue encontrado. Altura actual de la cadena de bloques: " << current_height << ", pedido: " << height << std::endl;
    return false;
  }

  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_block_by_hash(const std::string& arg)
{
  Crypto::Hash block_hash;
  if (!parse_hash256(arg, block_hash)) {
    return false;
  }

  std::list<Crypto::Hash> block_ids;
  block_ids.push_back(block_hash);
  std::list<CryptoNote::Block> blocks;
  std::list<Crypto::Hash> missed_ids;
  m_core.get_blocks(block_ids, blocks, missed_ids);

  if (1 == blocks.size())
  {
    print_as_json(blocks.front());
  } else
  {
    std::cout << "bloque no fue encontrado: " << arg << std::endl;
    return false;
  }

  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_block(const std::vector<std::string> &args) {
  if (args.empty()) {
    std::cout << "esperado: print_block (<block_hash> | <block_height>)" << std::endl;
    return true;
  }

  const std::string &arg = args.front();
  try {
    uint32_t height = boost::lexical_cast<uint32_t>(arg);
    print_block_by_height(height);
  } catch (boost::bad_lexical_cast &) {
    print_block_by_hash(arg);
  }

  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_tx(const std::vector<std::string>& args)
{
  if (args.empty()) {
    std::cout << "esperado: print_tx <transaction hash>" << std::endl;
    return true;
  }

  const std::string &str_hash = args.front();
  Crypto::Hash tx_hash;
  if (!parse_hash256(str_hash, tx_hash)) {
    return true;
  }

  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(tx_hash);
  std::list<CryptoNote::Transaction> txs;
  std::list<Crypto::Hash> missed_ids;
  m_core.getTransactions(tx_ids, txs, missed_ids, true);

  if (1 == txs.size()) {
    print_as_json(txs.front());
  } else {
    std::cout << "transaccion no fue encontrada: <" << str_hash << '>' << std::endl;
  }

  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_pool(const std::vector<std::string>& args)
{
  logger(Logging::INFO) << "Estado del grupo: " << ENDL << m_core.print_pool(false);
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::print_pool_sh(const std::vector<std::string>& args)
{
  logger(Logging::INFO) << "Estado del grupo " << ENDL << m_core.print_pool(true);
  return true;
}
//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::start_mining(const std::vector<std::string> &args) {
  if (!args.size()) {
    std::cout << "Por favor, especifique la direccion de la billetera para minar: start_mining <addr> [threads=1]" << std::endl;
    return true;
  }

  CryptoNote::AccountPublicAddress adr;
  if (!m_core.currency().parseAccountAddressString(args.front(), adr)) {
    std::cout << "la direccion de la cuenta de destino tiene un formato incorrecto" << std::endl;
    return true;
  }

  size_t threads_count = 1;
  if (args.size() > 1) {
    bool ok = Common::fromString(args[1], threads_count);
    threads_count = (ok && 0 < threads_count) ? threads_count : 1;
  }

  m_core.get_miner().start(adr, threads_count);
  return true;
}

//--------------------------------------------------------------------------------
bool DaemonCommandsHandler::stop_mining(const std::vector<std::string>& args) {
  m_core.get_miner().stop();
  return true;
}

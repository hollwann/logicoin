// Copyright (c) 2018, Logicoin

#include "TransfersSubscription.h"
#include "IWalletLegacy.h"

using namespace Crypto;

namespace CryptoNote {

TransfersSubscription::TransfersSubscription(const CryptoNote::Currency& currency, Logging::ILogger& logger, const AccountSubscription& sub)
  : subscription(sub), logger(logger, "TransfersSubscription"), transfers(currency, logger, sub.transactionSpendableAge) {}


SynchronizationStart TransfersSubscription::getSyncStart() {
  return subscription.syncStart;
}

void TransfersSubscription::onBlockchainDetach(uint32_t height) {
  std::vector<Hash> deletedTransactions = transfers.detach(height);
  for (auto& hash : deletedTransactions) {
    m_observerManager.notify(&ITransfersObserver::onTransactionDeleted, this, hash);
  }
}

void TransfersSubscription::onError(const std::error_code& ec, uint32_t height) {
  if (height != WALLET_LEGACY_UNCONFIRMED_TRANSACTION_HEIGHT) {
  transfers.detach(height);
  }
  m_observerManager.notify(&ITransfersObserver::onError, this, height, ec);
}

bool TransfersSubscription::advanceHeight(uint32_t height) {
  return transfers.advanceHeight(height);
}

const AccountKeys& TransfersSubscription::getKeys() const {
  return subscription.keys;
}

bool TransfersSubscription::addTransaction(const TransactionBlockInfo& blockInfo, const ITransactionReader& tx,
                                           const std::vector<TransactionOutputInformationIn>& transfersList) {
  bool added = transfers.addTransaction(blockInfo, tx, transfersList);
  if (added) {
    m_observerManager.notify(&ITransfersObserver::onTransactionUpdated, this, tx.getTransactionHash());
  }

  return added;
}

AccountPublicAddress TransfersSubscription::getAddress() {
  return subscription.keys.address;
}

ITransfersContainer& TransfersSubscription::getContainer() {
  return transfers;
}

void TransfersSubscription::deleteUnconfirmedTransaction(const Hash& transactionHash) {
  if (transfers.deleteUnconfirmedTransaction(transactionHash)) {
    m_observerManager.notify(&ITransfersObserver::onTransactionDeleted, this, transactionHash);
  }
}

void TransfersSubscription::markTransactionConfirmed(const TransactionBlockInfo& block, const Hash& transactionHash,
                                                     const std::vector<uint32_t>& globalIndices) {
  transfers.markTransactionConfirmed(block, transactionHash, globalIndices);
  m_observerManager.notify(&ITransfersObserver::onTransactionUpdated, this, transactionHash);
}

}

// Copyright (c) 2018, Logicoin

#pragma once

namespace CryptoNote
{
  struct NOTIFY_NEW_BLOCK_request;
  struct NOTIFY_NEW_TRANSACTIONS_request;

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct i_cryptonote_protocol {
    virtual void relay_block(NOTIFY_NEW_BLOCK_request& arg) = 0;
    virtual void relay_transactions(NOTIFY_NEW_TRANSACTIONS_request& arg) = 0;
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct cryptonote_protocol_stub: public i_cryptonote_protocol {
    virtual void relay_block(NOTIFY_NEW_BLOCK_request& arg) override {}
    virtual void relay_transactions(NOTIFY_NEW_TRANSACTIONS_request& arg) override {}
  };
}

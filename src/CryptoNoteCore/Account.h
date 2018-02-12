// Copyright (c) 2018, Logicoin


#pragma once

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "crypto/crypto.h"

namespace CryptoNote {

  class ISerializer;

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class AccountBase {
  public:
    AccountBase();
    void generate();
	void generateDeterministic();
	Crypto::SecretKey generate_key(const Crypto::SecretKey& recovery_key = Crypto::SecretKey(), bool recover = false, bool two_random = false);

    const AccountKeys& getAccountKeys() const;
    void setAccountKeys(const AccountKeys& keys);
    uint64_t get_createtime() const { return m_creation_timestamp; }
    void set_createtime(uint64_t val) { m_creation_timestamp = val; }
    void serialize(ISerializer& s);

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int /*ver*/) {
      a & m_keys;
      a & m_creation_timestamp;
    }

  private:
    void setNull();
    AccountKeys m_keys;
    uint64_t m_creation_timestamp;
  };
}

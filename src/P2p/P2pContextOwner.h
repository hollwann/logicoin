// Copyright (c) 2018, Logicoin

#pragma once

#include <list>
#include <memory>

namespace CryptoNote {

class P2pContext;

class P2pContextOwner {
public:

  typedef std::list<std::unique_ptr<P2pContext>> ContextList;

  P2pContextOwner(P2pContext* ctx, ContextList& contextList);
  P2pContextOwner(P2pContextOwner&& other);
  P2pContextOwner(const P2pContextOwner& other) = delete;
  ~P2pContextOwner();

  P2pContext& get();
  P2pContext* operator -> ();

private:

  ContextList& contextList;
  ContextList::iterator contextIterator;
};

}

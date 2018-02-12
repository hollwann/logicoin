// Copyright (c) 2018, Logicoin

#include "RemoteEventLock.h"
#include <cassert>
#include <mutex>
#include <condition_variable>
#include <System/Dispatcher.h>
#include <System/Event.h>

namespace System {

RemoteEventLock::RemoteEventLock(Dispatcher& dispatcher, Event& event) : dispatcher(dispatcher), event(event) {
  std::mutex mutex;
  std::condition_variable condition;
  bool locked = false;

  dispatcher.remoteSpawn([&]() {
    while (!event.get()) {
      event.wait();
    }

    event.clear();
    mutex.lock();
    locked = true;
    condition.notify_one();
    mutex.unlock();
  });

  std::unique_lock<std::mutex> lock(mutex);
  while (!locked) {
    condition.wait(lock);
  }
}

RemoteEventLock::~RemoteEventLock() {
  Event* eventPointer = &event;
  dispatcher.remoteSpawn([=]() {
    assert(!eventPointer->get());
    eventPointer->set();
  });
}

}

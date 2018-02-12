// Copyright (c) 2018, Logicoin

#pragma once

namespace System {

class Event;

class EventLock {
public:
  explicit EventLock(Event& event);
  ~EventLock();
  EventLock& operator=(const EventLock&) = delete;

private:
  Event& event;
};

}

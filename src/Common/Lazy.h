// Copyright (c) 2018, Logicoin

#pragma once

#include <functional>
#include <stdexcept>

namespace {

// Exception thrown on attempt to access an uninitialized Lazy
struct uninitialized_lazy_exception : public std::runtime_error
{
    uninitialized_lazy_exception()
        : std::runtime_error("Uninitialized lazy value.")
    {}
};

template<typename T>
struct Lazy
{
    // Default constructor
    Lazy()
        : m_bInitialized(false)
        , m_initializer(DefaultInitializer)
        , m_deinitializer(DefaultDeinitializer)
    {}

    // Construct with initializer and optional deinitializer functor
    Lazy(std::function<T(void)> initializer, std::function<void(T&)> deinitializer = DefaultDeinitializer)
        : m_bInitialized(false)
        , m_initializer(initializer)
        , m_deinitializer(deinitializer)
    {}

    // Copy constructor
    Lazy(const Lazy& o)
        : m_bInitialized(false)
        , m_initializer(o.m_initializer)
        , m_deinitializer(o.m_deinitializer)
    {
        if (o.m_bInitialized)
            construct(*o.valuePtr());
    }

    // Assign from Lazy<T>
    Lazy& operator=(const Lazy<T>& o)
    {
        destroy();
        m_initializer   = o.m_initializer;
        m_deinitializer = o.m_deinitializer;
        if (o.m_bInitialized)
            construct(*o.valuePtr());
        return *this;
    }

    // Construct from T
    Lazy(const T& v)
        : m_bInitialized(false)
        , m_initializer(DefaultInitializer)
        , m_deinitializer(DefaultDeinitializer)
    {
        construct(v);
    }

    // Assign from T
    T& operator=(const T& value)
    {
        construct(value);
        return *valuePtr();
    }

    // Destruct and deinitialize
    ~Lazy()
    {
        destroy();
    }

    // Answer true if initialized, either implicitly via function or explicitly via assignment
    bool isInitialized() const
    {
        return m_bInitialized;
    }

    // Force initialization, if not already done, and answer with the value
    // Throws exception if not implicitly or explicitly initialized
    T& force() const
    {
        if (!m_bInitialized)
            construct(m_initializer());
        return *valuePtr();
    }

    // Implicitly force initialization and answer with value
    operator T&() const
    {
        return force();
    }

    // Get pointer to storage of T, regardless of initialized state
    T* operator &() const
    {
        return valuePtr();
    }

    // Force initialization state to true, e.g. if value initialized directly via pointer
    void forceInitialized()
    {
        m_bInitialized = true;
    }

private:
    mutable char            m_value[sizeof(T)];
    mutable bool            m_bInitialized;
    std::function<T(void)>  m_initializer;
    std::function<void(T&)> m_deinitializer;

    // Get pointer to storage of T
    T* valuePtr() const
    {
        return static_cast<T*>(static_cast<void*>(&m_value));
    }

    // Call copy constructor for T.  Deinitialize self first, if necessary.
    void construct(const T& value) const
    {
        destroy();
        new (valuePtr()) T(value);
        m_bInitialized = true;
    }
    void construct(T&& value) const
    {
        destroy();
        new (valuePtr()) T(std::move(value));
        m_bInitialized = true;
    }

    // If initialized, call deinitializer and then destructor for T
    void destroy() const
    {
        if (m_bInitialized)
        {
            m_deinitializer(*valuePtr());
            valuePtr()->~T();
            m_bInitialized = false;
        }
    }

    // Inititializer if none specified; throw exception on attempt to access uninitialized lazy
    static T DefaultInitializer()
    {
        throw uninitialized_lazy_exception();
    }

    // Deinitialize if none specified; does nothing
    static void DefaultDeinitializer(T&)
    {
    }
};

}
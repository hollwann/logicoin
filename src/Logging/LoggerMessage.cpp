// Copyright (c) 2018, Logicoin

#include "LoggerMessage.h"

namespace Logging {

LoggerMessage::LoggerMessage(ILogger& logger, const std::string& category, Level level, const std::string& color)
	: std::ostream(this)
	, std::streambuf()
	, m_logger(logger)
	, m_sCategory(category)
	, m_nLogLevel(level)
	, m_sMessage(color)
	, m_tmTimeStamp(boost::posix_time::microsec_clock::local_time())
	, m_bGotText(false)
{}
#ifndef __linux__

LoggerMessage::LoggerMessage(LoggerMessage&& other)
	: std::ostream(std::move(other))
	, std::streambuf(std::move(other))
	, m_logger(other.m_logger)
	, m_sCategory(other.m_sCategory)
	, m_nLogLevel(other.m_nLogLevel)
	, m_sMessage(other.m_sMessage)
	, m_tmTimeStamp(boost::posix_time::microsec_clock::local_time())
	, m_bGotText(false)
{
	std::ostream::rdbuf(this);
}

#else
LoggerMessage::LoggerMessage(LoggerMessage&& other)
  : std::ostream(nullptr)
  , std::streambuf()
  , m_sCategory(other.m_sCategory)
  , m_nLogLevel(other.m_nLogLevel)
  , m_logger(other.m_logger)
  , m_sMessage(other.m_sMessage)
  , m_tmTimeStamp(boost::posix_time::microsec_clock::local_time())
  , m_bGotText(false) {
  if (this != &other) {
    _M_tie = nullptr;
    _M_streambuf = nullptr;

    //ios_base swap
    std::swap(_M_streambuf_state, other._M_streambuf_state);
    std::swap(_M_exception, other._M_exception);
    std::swap(_M_flags, other._M_flags);
    std::swap(_M_precision, other._M_precision);
    std::swap(_M_width, other._M_width);

    std::swap(_M_callbacks, other._M_callbacks);
    std::swap(_M_ios_locale, other._M_ios_locale);
    //ios_base swap

    //streambuf swap
    char *_Pfirst = pbase();
    char *_Pnext = pptr();
    char *_Pend = epptr();
    char *_Gfirst = eback();
    char *_Gnext = gptr();
    char *_Gend = egptr();

    setp(other.pbase(), other.epptr());
    other.setp(_Pfirst, _Pend);

    setg(other.eback(), other.gptr(), other.egptr());
    other.setg(_Gfirst, _Gnext, _Gend);

    std::swap(_M_buf_locale, other._M_buf_locale);
    //streambuf swap

    std::swap(_M_fill, other._M_fill);
    std::swap(_M_tie, other._M_tie);
  }
  _M_streambuf = this;
}
#endif

LoggerMessage::~LoggerMessage()
{
	if (m_bGotText)
		(*this) << std::endl;
}

int LoggerMessage::sync()
{
	m_logger(m_sCategory, m_nLogLevel, m_tmTimeStamp, m_sMessage);
	m_bGotText = false;
	m_sMessage = Logging::DEFAULT;
	return 0;
}

std::streamsize LoggerMessage::xsputn(const char* s, std::streamsize n)
{
	m_bGotText = true;
	m_sMessage.append(s, n);
	return n;
}

int LoggerMessage::overflow(int c)
{
	m_bGotText = true;
	m_sMessage += static_cast<char>(c);
	return 0;
}

} //Logging

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

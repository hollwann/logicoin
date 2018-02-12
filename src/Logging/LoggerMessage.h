// Copyright (c) 2018, Logicoin

#pragma once

#include "ILogger.h"
#include <iostream>

namespace Logging {

class LoggerMessage : public std::ostream, std::streambuf
{
public:
	LoggerMessage(ILogger& logger, const std::string& category, Level level, const std::string& color);
	LoggerMessage(LoggerMessage&& other);
	~LoggerMessage();
	LoggerMessage(const LoggerMessage&) = delete;
	LoggerMessage& operator=(const LoggerMessage&) = delete;

private:
	int sync() override;
	std::streamsize xsputn(const char* s, std::streamsize n) override;
	int overflow(int c) override;

private:
	ILogger& m_logger;
	const std::string m_sCategory;
	Level m_nLogLevel;
	std::string m_sMessage;
	boost::posix_time::ptime m_tmTimeStamp;
	bool m_bGotText;
};

} //Logging

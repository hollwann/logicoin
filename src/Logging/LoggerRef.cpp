// Copyright (c) 2018, Logicoin

#include "LoggerRef.h"

namespace Logging {

LoggerRef::LoggerRef(ILogger& logger, const std::string& category) 
	: m_logger(&logger)
	, m_sCategory(category)
{}

LoggerMessage LoggerRef::operator()(Level level, const std::string& color) const
{
	return LoggerMessage(*m_logger, m_sCategory, level, color);
}

ILogger& LoggerRef::getLogger() const
{
	return *m_logger;
}

} //Logging

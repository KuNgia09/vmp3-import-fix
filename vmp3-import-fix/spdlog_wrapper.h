#pragma once

#define MYSPDLOG_LOG_FILE
#ifdef MYSPDLOG_LOG_FILE

#define MYSPDLOG_INFO logger->info
#define MYSPDLOG_WARN logger->warn
#define MYSPDLOG_ERROR logger->error
#else
#define MYSPDLOG_INFO spdlog::info
#define MYSPDLOG_WARN spdlog::warn
#define MYSPDLOG_ERROR spdlog::error

#endif 
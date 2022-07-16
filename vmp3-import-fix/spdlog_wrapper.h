#pragma once

#define SPDLOG_LOG_FILE
#ifdef SPDLOG_LOG_FILE

#define SPDLOG_INFO logger->info
#define SPDLOG_WARN logger->warn
#define SPDLOG_ERROR logger->error
#else
#define SPDLOG_INFO spdlog::info
#define SPDLOG_WARN spdlog::warn
#define SPDLOG_ERROR spdlog::error

#endif 
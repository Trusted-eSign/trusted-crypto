#include "common.h"

#ifndef COMMON_LOG_H_INCLUDE
#define COMMON_LOG_H_INCLUDE

#include <fstream>

class CTWRAPPER_API Logger;

class LoggerLevel
{
public:
    enum LOGGER_LEVEL
    {
	Null = 0,
	Error = 1,
	Warning = 2,
	Info = 4,
	Debug = 8,
	Trace = 16,
	OpenSSL = 32,
	All = Trace | Error | Warning | Info | Debug | OpenSSL
    };
};

class CTWRAPPER_API Logger{
//methods
public:
	Logger(){ init(); };
	~Logger();
	//Handle<std::string> filename(const char*path);
	void write(LoggerLevel::LOGGER_LEVEL level, const char* fn, const char *msg, ...);
	void write(LoggerLevel::LOGGER_LEVEL level, const char* fn, const char *msg, va_list);
	void start(const char *filename, int levels);
	void stop();
	void clear();

	void debug(const char* fn, const char *msg, ...);
	void error(const char* fn, const char *msg, ...);
	void warn(const char* fn, const char *msg, ...);
	void info(const char* fn, const char *msg, ...);

protected:
	void init();

//properties
public:
	int levels;
protected: 
	Handle<std::string> _filename;
	//Handle<std::ofstream> _file;
	FILE* _file;
};

//GLOBAL LOG
extern Logger *logger;

#define LOGGER_DEBUG(msg, ...) \
	logger->debug(__FUNCTION__, msg, ## __VA_ARGS__);

#define LOGGER_ERROR(msg, ...) \
	logger->error(__FUNCTION__, msg, ## __VA_ARGS__);

#define LOGGER_INFO(msg, ...) \
	logger->info(__FUNCTION__, msg, ## __VA_ARGS__);

#define LOGGER_WARN(msg, ...) \
	logger->warn(__FUNCTION__, msg, ## __VA_ARGS__);

#define LOGGER_OPENSSL(msg, ...) \
	logger->write(LoggerLevel::OpenSSL, __FUNCTION__, #msg, ## __VA_ARGS__);

#define LOGGER_TRACE(msg, ...) \
	logger->write(LoggerLevel::Trace, __FUNCTION__, msg, ## __VA_ARGS__);

#define LOGGER_FN_BEGIN() \
	LOGGER_TRACE("Begin")

#define LOGGER_FN_END() \
	LOGGER_TRACE("End")

#define LOGGER_FN() \
	LoggerFunction __logger_fn(logger, __FUNCTION__);

class CTWRAPPER_API LoggerFunction{
public:
	LoggerFunction(Logger *logger, const char *fn);
	~LoggerFunction();
protected:
	Handle<std::string> _fn = NULL;
	Logger *_logger = NULL;
};
#endif //!COMMON_LOG_H_INCLUDE

#include "../stdafx.h"

#include <ctime>

#include "wrapper/common/common.h"

static void writeLoggerLevel(FILE *file, LoggerLevel::LOGGER_LEVEL level){
	std::string str_level("");
	switch (level){
	case LoggerLevel::Debug:
		str_level = "DEBUG";
		break;
	case LoggerLevel::Error:
		str_level = "ERROR";
		break;
	case LoggerLevel::Info:
		str_level = "INFO";
		break;
	case LoggerLevel::Warning:
		str_level = "WARNING";
		break;
	case LoggerLevel::OpenSSL:
		str_level = "OPENSSL";
		break;
	case LoggerLevel::Trace:
		str_level = "TRACE";
		break;
	default:
		//char *custom = (char *)malloc(20);
		//sprintf(custom, "UNKNOWN", level);
		//str_level = custom;
		str_level = "UNKNOWN";
		//free(custom);
	}
	str_level += "\t";
	fwrite(str_level.c_str(), 1, str_level.length(), file);
}

static void writeLoggerTime(FILE *file, time_t &datetime){
	struct tm aTm;
#ifdef _WIN32
	localtime_s(&aTm, &datetime);
#else
	localtime_r(&datetime, &aTm);
#endif
	char _time[30];
	strftime(_time, 30, "%Y-%m-%d %H:%M:%S ", &aTm);
	fwrite(_time, 1, strlen(_time), file);
}

static void writeLoggerTime(FILE *file){
	time_t curTime = time(NULL);
	writeLoggerTime(file, curTime);
}

static void writeLoggerFunction(FILE *file, const char* fn){
	fwrite(fn, 1, strlen(fn), file);
	fwrite(": ", 1, 2, file);
}

Logger::Logger(const char* path){};
Logger::~Logger(){};

void Logger::init(){
	levels = LoggerLevel::Null;
	_file = NULL;
};

void Logger::start(const char *filename, int levels){
	_file = fopen(filename, "a+");
	_filename = new std::string(filename);
	this->levels = levels;
}

void Logger::stop(){
	if (_file){
		fclose(_file);
		_file = NULL;
	}
}

void Logger::clear(){
	fclose(_file);
	_file = fopen(this->_filename->c_str(), "w+");
}

void Logger::write(LoggerLevel::LOGGER_LEVEL level, const char* fn, const char *msg, ...){
	va_list args;
	va_start(args, msg);
	this->write(level, fn, msg, args);
	va_end(args);
}

void Logger::write(LoggerLevel::LOGGER_LEVEL level, const char* fn, const char *msg, va_list args){
	if (_file && level && (level & this->levels)){
		writeLoggerTime(_file);
		writeLoggerLevel(_file, level);
		writeLoggerFunction(_file, fn);
		char *out = (char *)malloc(1024);
		vsnprintf(out, 1024, msg, args);
		fwrite(out, 1, strlen(out), _file);
		free(out);
		std::string newLine("\n");
		fwrite(newLine.c_str(), 1, newLine.length(), _file);
		fflush(_file);
	}
}

void Logger::debug(const char* fn, const char *msg, ...){
	va_list args;
	va_start(args, msg);
	this->write(LoggerLevel::Debug, fn, msg, args);
	va_end(args);
}

void Logger::error(const char* fn, const char *msg, ...){
	va_list args;
	va_start(args, msg);
	this->write(LoggerLevel::Error, fn, msg, args);
	va_end(args);
}

void Logger::warn(const char* fn, const char *msg, ...){
	va_list args;
	va_start(args, msg);
	this->write(LoggerLevel::Warning, fn, msg, args);
	va_end(args);
}

void Logger::info(const char* fn, const char *msg, ...){
	va_list args;
	va_start(args, msg);
	this->write(LoggerLevel::Info, fn, msg, args);
	va_end(args);
}

LoggerFunction::LoggerFunction(Logger *logger, const char*fn){
	_fn = new std::string(fn);
	_logger = logger;
	_logger->write(LoggerLevel::Trace, _fn->c_str(), "Begin");
	//_logger->info(_fn->c_str(), "Begining");
}

LoggerFunction::~LoggerFunction(){
	_logger->write(LoggerLevel::Trace, _fn->c_str(), "End");
}

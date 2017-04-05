#include "../stdafx.h"

#include <ctime>

#include "wrapper/common/log.h"

Logger *logger = new Logger();

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

Logger::~Logger(){
	delete logger;
};

void Logger::init() {
	this->levels = LoggerLevel::Null;
	this->_file = NULL;
	this->_filename = NULL;
};

void Logger::start(const char *filename, int levels){
	if ((this->_file = fopen(filename, "a+")) == NULL) {
		THROW_EXCEPTION(0, Logger, NULL, "Error open file");
	};
	this->_filename = new std::string(filename);
	this->levels = levels;

	logger = this;
}

void Logger::stop(){
	if (this->_file){
		fclose(this->_file);
		this->_file = NULL;
	}
	this->levels = LoggerLevel::Null;
}

void Logger::clear(){
	if (this->_file){
		fclose(this->_file);
		this->_file = NULL;
	}
	if ((this->_file = fopen(this->_filename->c_str(), "w+")) == NULL) {
		THROW_EXCEPTION(0, Logger, NULL, "Error open file");
	};
}

void Logger::write(LoggerLevel::LOGGER_LEVEL level, const char* fn, const char *msg, ...){
	va_list args;
	va_start(args, msg);
	this->write(level, fn, msg, args);
	va_end(args);
}

void Logger::write(LoggerLevel::LOGGER_LEVEL level, const char* fn, const char *msg, va_list args){
	if (this->_file && level && (level & this->levels)){
		writeLoggerTime(this->_file);
		writeLoggerLevel(this->_file, level);
		writeLoggerFunction(this->_file, fn);
		char *out = (char *)malloc(1024);
		vsnprintf(out, 1024, msg, args);
		fwrite(out, 1, strlen(out), this->_file);
		free(out);
		std::string newLine("\n");
		fwrite(newLine.c_str(), 1, newLine.length(), this->_file);
		fflush(this->_file);
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
	this->_fn = new std::string(fn);
	this->_logger = logger;
	this->_logger->write(LoggerLevel::Trace, this->_fn->c_str(), "Begin");
}

LoggerFunction::~LoggerFunction(){
	this->_logger->write(LoggerLevel::Trace, this->_fn->c_str(), "End");
}

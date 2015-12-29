#include "../stdafx.h"

#include <stdarg.h>

#include "excep.h"

//Exception::Exception(int code, std::string msg, std::string className, std::string methodName, Exception* exception, ...) {
//va_list last_args;

// � ������ ���� ��� char* �������� �� const char*

Exception::Exception(
		bool fromOpenSSL,
		const char* file,
		int line,
		int errorNum,
		const char *className,
		const char *methodName,
		Handle<Exception> stack,
		const char* message,
		...)
//: std::runtime_error("") {
{
	this->except_ = NULL;
	this->file_ = file;
	this->line_ = line;
	this->code_ = errorNum;
	this->class_ = className;
	this->method_ = methodName;
	this->except_ = stack;

	va_list args;
	char msg[256] = {0};

	va_start(args, message);
#ifdef _WIN32
	vsprintf_s(msg, message, args);
#else
	vsprintf(msg, message, args);
#endif
	va_end(args);

	this->fillDescription(msg, fromOpenSSL);
}

const std::string Exception::description() {
	return this->description_;
}

const char *Exception::what() const throw () {
	return this->description_.c_str();
}

void Exception::fillDescription(
		const std::string& message,
		bool fromOpenSSL)
{
	char desc[512] = {0};
#ifdef _WIN32
	sprintf_s(desc, "\n%s:%d\n", this->file_.c_str(), this->line_);
#else
	sprintf(desc, "\n%s:%d\n", this->file_.c_str(), this->line_);
#endif
	this->description_ = this->method_ + " " + message + desc;

	if (fromOpenSSL) {
		this->description_ += "\n" + *OpenSSL::printErrors();
	}

	if (!this->except_.isEmpty()) {
		this->description_ += this->except_->description_;
	}
}

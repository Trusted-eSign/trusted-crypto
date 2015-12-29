#include "common.h"

#ifndef CMS_COMMON_EXCEP_H_INCLUDED
#define  CMS_COMMON_EXCEP_H_INCLUDED

#include <stdio.h>
#include "refcount.h"

#define ERROR_PARAMETER_NULL "Parameter %d can not be NULL"

#define THROW_EXCEPTION(code, className, stack, msg, ...){\
	LOGGER_ERROR(msg, ## __VA_ARGS__); \
	Handle<Exception> __e = new Exception(false, __FILE__, __LINE__, code, #className, __FUNCTION__, stack, msg, ## __VA_ARGS__);\
	throw __e;}

#define THROW_PARAMETER_NULL(className, stack, paramNum)\
	THROW_EXCEPTION(0, className, stack, ERROR_PARAMETER_NULL, paramNum)

#define THROW_OPENSSL_EXCEPTION(code, className, stack, msg, ...) \
	{ \
		Handle<Exception> __e = new Exception(true, __FILE__, __LINE__, code, #className, __FUNCTION__, stack, msg, ## __VA_ARGS__); \
		LOGGER_WARN("%s", __e->what()); \
		throw __e; \
	}

#define CATCH_EXCEPTIONS(actions) \
	catch (Handle<Exception>& ex)\
	{ \
		std::string strWhat = ex->what(); \
		LOGGER_ERROR("Exception catched: %s", strWhat.c_str()); \
		actions \
	} \
	catch (std::exception& ex)\
	{ \
		std::string strWhat = ex.what(); \
		LOGGER_ERROR("Exception catched: %s", strWhat.c_str()); \
		actions \
	} \
	catch (...)\
	{ \
		std::string strWhat = "Unknown exception"; \
		LOGGER_ERROR("Unknown exception catched"); \
		actions \
	}

//class CTWRAPPER_API Exception: public std::runtime_error {
class CTWRAPPER_API Exception{
public:
	// � ������ ���� ��� char* �������� �� const char*
	Exception(
			bool fromOpenSSL,
			const char* file,
			int line,
			int errorNum,
			const char *className,
			const char *methodName,
			Handle<Exception>,
			const char* message,
			...);

	~Exception() throw () {
		//delete this->except_;
	};

	const std::string description();
	void fillDescription(
			const std::string& message,
			bool fromOpenSSL);
	const char *what() const throw ();
	int code(){
		return this->code_;
	}

protected:

	std::string description_;
	std::string class_;
	std::string method_;
	int line_;
	std::string file_;
	va_list arguments_;
	int code_;
	Handle<Exception> except_; //Handle ||| sd::list
};

#endif //!CMS_COMMON_EXCEP_H_INCLUDED

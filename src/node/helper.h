#ifndef NW_HELPER_H_INCLUDED
#define NW_HELPER_H_INCLUDED

#include <v8.h>
#include "../wrapper/common/common.h"

#define LOGGER_ARG(name) LOGGER_INFO("Param: %s", name)

/**
* Schedule an "allocation failed" exception. This (tries) to allocate
* as well, which very well could (probably will) fail too, but it's the
* best we can do in a bad situation.
*/
void scheduleAllocException();

/**
* Get a string out of args[] at the given index, converted to a
* freshly-allocated (char *). Returns a non-null pointer on
* success. On failure, schedules an exception and returns NULL.
*/
char *copyBufferToUtf8String(const v8::Local<v8::String> str);
v8::Local<v8::Object> stringToBuffer(Handle<std::string> v);
//std::string getFileName(const v8::Local<v8::String> str);

Handle<std::string> getString(v8::Local<v8::String> v8String);
Handle<std::string> getBuffer(v8::Local<v8::Value> v8Value);

Handle<std::string> getErrorText(Handle<Exception> e);

#define METHOD_BEGIN() \
	LOGGER_FN();


#define TRY_END() \
	TRY_END_HANDLE_EXCEPTION() \
	TRY_END_DEFAULT_EXCEPTION() \
	info.GetReturnValue().SetUndefined();

#define TRY_END_HANDLE_EXCEPTION()\
	catch(Handle<Exception> e){ \
		Nan::ThrowError(getErrorText(e)->c_str()); \
		return;}

#define TRY_END_DEFAULT_EXCEPTION()\
	catch(...){\
		Nan::ThrowError("Unknown error"); \
		return;}

#define UNWRAP_DATA(type) \
	LOGGER_TRACE("Unwrapp data");\
	W##type* __obj = (W##type*)Nan::GetInternalFieldPointer(info.This(), 0); \
	Handle<type> _this = __obj->data_; 

#define UNWRAP() \
	UNWRAP_DATA(typeof(this->childData));

#endif //NW_HELPER_H_INCLUDED

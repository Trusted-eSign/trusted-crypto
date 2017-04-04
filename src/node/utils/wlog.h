#ifndef UTILS_WLOG_H_INCLUDED
#define UTILS_WLOG_H_INCLUDED

#include <nan.h>
#include "wrap.h"
#include "../helper.h"

#include <wrapper/common/log.h>

WRAP_CLASS(Logger) {
public:
	WLogger(){};
	~WLogger(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Start);
	static NAN_METHOD(Stop);
	static NAN_METHOD(Clear);
};

#endif //!UTILS_WLOG_H_INCLUDED

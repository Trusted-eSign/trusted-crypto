#ifndef UTILS_WLOG_H_INCLUDED
#define  UTILS_WLOG_H_INCLUDED

#include "../../wrapper/common/common.h"

#include <nan.h>
#include "../helper.h"

class WLogger: public node::ObjectWrap
{
public:
	WLogger(){};
	~WLogger(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Start);
	static NAN_METHOD(Stop);
	static NAN_METHOD(Clear);

	static NAN_METHOD(Write);
	static NAN_METHOD(Info);
	static NAN_METHOD(Warn);
	static NAN_METHOD(Debug);
	static NAN_METHOD(Error);

	Handle<Logger> data_;
	
	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //!UTILS_WLOG_H_INCLUDED

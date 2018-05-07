#ifndef UTIL_WJWT_INCLUDED
#define UTIL_WJWT_INCLUDED

#include <nan.h>
#include "wrap.h"
#include "../helper.h"

#include <wrapper/utils/jwt.h>

WRAP_CLASS(Jwt){
public:
	WJwt(){};
	~WJwt(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(CheckLicense);
	static NAN_METHOD(CheckTrialLicense);
	static NAN_METHOD(GetExpirationTime);
	static NAN_METHOD(GetTrialExpirationTime);
	static NAN_METHOD(CreateTrialLicense);

};

#endif //!UTIL_WJWT_INCLUDED 

#ifndef UTIL_WCSP_INCLUDED
#define UTIL_WCSP_INCLUDED

#include <nan.h>
#include "wrap.h"
#include "../helper.h"

#include <wrapper/utils/csp.h>

WRAP_CLASS(Csp){
public:
	WCsp(){};
	~WCsp(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(IsGost2001CSPAvailable);
	static NAN_METHOD(IsGost2012_256CSPAvailable);
	static NAN_METHOD(IsGost2012_512CSPAvailable);

	static NAN_METHOD(CheckCPCSPLicense);
	static NAN_METHOD(GetCPCSPLicense);
};

#endif //!UTIL_WCSP_INCLUDED 

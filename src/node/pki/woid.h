#ifndef PKI_WOID_H_INCLUDED
#define  PKI_WOID_H_INCLUDED

#include "../../wrapper/pki/oid.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

class WOID: public Wrapper<OID>
{
public:
	WOID(){};
	~WOID(){};

	WRAP_NEW_INSTANCE(OID);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	// Properties
	static NAN_METHOD(GetLongName);
	static NAN_METHOD(GetShortName);
	static NAN_METHOD(GetValue);
};

#endif //PKI_WOID_H_INCLUDED
#ifndef PKI_WREVOKEDS_H_INCLUDED
#define PKI_WREVOKEDS_H_INCLUDED

#include "../../wrapper/pki/revokeds.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

class WRevokedCollection : public Wrapper < RevokedCollection >
{
public:
	WRevokedCollection(){};
	~WRevokedCollection(){};

	WRAP_NEW_INSTANCE(RevokedCollection);

	static const char* className;

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Items);
	static NAN_METHOD(Push);
	static NAN_METHOD(Pop);
	static NAN_METHOD(RemoveAt);
	static NAN_METHOD(Length);
};

#endif // PKI_WREVOKEDS_H_INCLUDED
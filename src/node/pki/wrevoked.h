#ifndef PKI_WREVOKED_H_INCLUDED
#define PKI_WREVOKED_H_INCLUDED

#include "../../wrapper/pki/revoked.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

WRAP_CLASS(Revoked){
public:
	WRevoked(){};
	~WRevoked(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Duplicate);
	static NAN_METHOD(GetRevocationDate);
	static NAN_METHOD(GetReason);

	WRAP_NEW_INSTANCE(Revoked);
};

#endif //PKI_WREVOKED_H_INCLUDED

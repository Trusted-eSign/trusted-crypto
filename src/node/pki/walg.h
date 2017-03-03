#ifndef PKI_WALG_H_INCLUDED
#define  PKI_WALG_H_INCLUDED

#include <wrapper/pki/alg.h>

#include <nan.h>
#include "../helper.h"

WRAP_CLASS(Algorithm)
{
public:
	WAlgorithm(){};
	~WAlgorithm(){};

	static const char* className;

	WRAP_NEW_INSTANCE(Algorithm);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	// Properties
	static NAN_METHOD(GetTypeId);
	static NAN_METHOD(GetName);

	// Methods
	static NAN_METHOD(Duplicate);
	static NAN_METHOD(IsDigest);
};

#endif //PKI_WALG_H_INCLUDED
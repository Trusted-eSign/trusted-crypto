#ifndef PKI_WALG_H_INCLUDED
#define  PKI_WALG_H_INCLUDED

#include "../../wrapper/pki/alg.h"

#include <nan.h>
#include "../helper.h"

#define CLASS_NAME_ALGORITHM "Algorithm"

class WAlgorithm : public node::ObjectWrap
{
public:
	WAlgorithm(){};
	~WAlgorithm(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	// Properties
	static NAN_METHOD(GetTypeId);
	static NAN_METHOD(GetName);

	// Methods
	static NAN_METHOD(Duplicate);
	static NAN_METHOD(IsDigest);

	Handle<Algorithm> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#endif //PKI_WALG_H_INCLUDED
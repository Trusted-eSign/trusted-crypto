#ifndef PKI_WATTR_H_INCLUDED
#define  PKI_WATTR_H_INCLUDED

#include <wrapper/pki/attr.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

class WAttribute : public Wrapper < Attribute > {
public:
	WAttribute(){};
	~WAttribute(){};

	static const char* className;

	WRAP_NEW_INSTANCE(Attribute);

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Duplicate);
	static NAN_METHOD(Export);
	static NAN_METHOD(Values);

	static NAN_METHOD(GetAsnType);
	static NAN_METHOD(SetAsnType);
	static NAN_METHOD(GetTypeId);
	static NAN_METHOD(SetTypeId);
};

#endif //PKI_WATTR_H_INCLUDED
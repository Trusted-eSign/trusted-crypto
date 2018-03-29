#ifndef PKI_WEXTS_H_INCLUDED
#define PKI_WEXTS_H_INCLUDED

#include <wrapper/pki/exts.h>

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

class WExtensionCollection : public Wrapper < ExtensionCollection >
{
public:
	WExtensionCollection(){};
	~WExtensionCollection(){};

	WRAP_NEW_INSTANCE(ExtensionCollection);

	static const char* className;

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Items);
	static NAN_METHOD(Push);
	static NAN_METHOD(Pop);
	static NAN_METHOD(RemoveAt);
	static NAN_METHOD(Length);
};

#endif //PKI_WEXTS_H_INCLUDED

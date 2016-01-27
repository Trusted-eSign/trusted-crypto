#ifndef CMS_W_SIGNERS_H_INCLUDED
#define CMS_W_SIGNERS_H_INCLUDED

#include "../../wrapper/cms/signers.h"

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

class WSignerCollection : public Wrapper < SignerCollection >
{
public:
	WSignerCollection(){};
	~WSignerCollection(){};

	WRAP_NEW_INSTANCE(SignerCollection);

	static const char* className;

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Items);
	static NAN_METHOD(Length);
};

#endif // CMS_W_SIGNERS_H_INCLUDED
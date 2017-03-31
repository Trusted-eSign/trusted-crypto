#ifndef COMMON_WOPENSSL_INCLUDED
#define COMMON_WOPENSSL_INCLUDED

#include <nan.h>
#include "../utils/wrap.h"
#include "../helper.h"

#include <wrapper/common/openssl.h>

WRAP_CLASS(OpenSSL){
public:
	WOpenSSL(){};
	~WOpenSSL(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Run);
	static NAN_METHOD(Stop);
	static NAN_METHOD(PrintErrors);
};

#endif //!COMMON_WOPENSSL_INCLUDED

//#ifndef CMS_PKI_CSR_H_INCLUDED
//#define CMS_PKI_CSR_H_INCLUDED

#include "../../wrapper/pki/csr.h"

#include <node.h>
#include <v8.h>
#include <node_object_wrap.h>
#include <nan.h>
#include "../helper.h"

class WCSR : public node::ObjectWrap{
public:
	WCSR(){};
	~WCSR(){};

	static void Init(v8::Handle<v8::Object>);
	static NAN_METHOD(New);

	static NAN_METHOD(Save);
	static NAN_METHOD(GetEncoded);

	Handle<CSR> data_;

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

//#endif //CMS_PKI_CSR_H_INCLUDED

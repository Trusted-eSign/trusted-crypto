#ifndef UTIL_WRAPPER_INCLUDED
#define  UTIL_WRAPPER_INCLUDED

#include <nan.h>
#include "../../wrapper/common/common.h"
#include "../helper.h"

template<typename T>
class Wrapper : public node::ObjectWrap{
protected:
	typedef T childData;
	static const char *className;
public:
	Handle<T> data_;

	static void Init(v8::Handle<v8::Object>){ LOGGER_FN();};

	template<typename CT>
	static v8::Local<v8::Object> NewInstance(){
		LOGGER_FN();

		LOGGER_INFO("Create new instance of JS Pki");
		v8::Local<v8::Object> v8Module = Nan::New<v8::Object>();
		CT::Init(v8Module);
		v8::Local<v8::Object> v8Object = Nan::Get(v8Module, Nan::New(CT::className).ToLocalChecked()).ToLocalChecked()->ToObject()->CallAsConstructor(0, NULL)->ToObject();
		return v8Object;
	}

	template<typename CT, typename CDT>
	static v8::Local<v8::Object> NewInstance(Handle<CDT> data){
		LOGGER_FN();
		
		v8::Local<v8::Object> v8Object = CT::NewInstance();
		
		LOGGER_INFO("Set internal data for JS Object");
		CT* wObject = (CT*)Nan::GetInternalFieldPointer(v8Object, 0);
		wObject->data_ = data;

		return v8Object;
	}

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

#define WRAP_CLASS(type)											\
	class W##type : public Wrapper<type>

#define WRAP_NEW_INSTANCE(className)										\
	static v8::Local<v8::Object> NewInstance(){								\
		return Wrapper::NewInstance < W##className >();						\
	};																		\
	static v8::Local<v8::Object> NewInstance(Handle<className> data){		\
		return Wrapper::NewInstance < W##className, className >(data);		\
	};


#endif //!UTIL_WRAPPER_INCLUDED 

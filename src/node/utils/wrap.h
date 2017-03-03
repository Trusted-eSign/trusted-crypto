#ifndef UTIL_WRAPPER_INCLUDED
#define  UTIL_WRAPPER_INCLUDED

#include <nan.h>
#include <wrapper/common/common.h>
#include "../helper.h"

template<typename T>
class Wrapper : public node::ObjectWrap{
protected:
	typedef T childData;
public:
	Handle<T> data_;

	static void Init(v8::Handle<v8::Object>){ LOGGER_FN(); };

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
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
};

#define WRAP_constructor()																\
	static inline Nan::Persistent<v8::Function> & constructor() {						\
		static Nan::Persistent<v8::Function> my_constructor;							\
		return my_constructor;															\
	}																					

#define WRAP_CLASS(type)																\
	class W##type : public Wrapper<type>

#define WRAP_NEW_INSTANCE_null()														\
	static v8::Local<v8::Object> NewInstance() {										\
		v8::Local<v8::Function> cons = Nan::New(constructor());							\
		return Nan::NewInstance(cons).ToLocalChecked();									\
	}																					

#define WRAP_NEW_INSTANCE_args()												\
	static v8::Local<v8::Object> NewInstance(int argc, v8::Local<v8::Value> argv[]) {	\
		v8::Local<v8::Function> cons = Nan::New(constructor());							\
		return Nan::NewInstance(cons, argc, argv).ToLocalChecked();						\
	}																					

#define WRAP_NEW_INSTANCE_data(className)												\
	static v8::Local<v8::Object> NewInstance(Handle<className> data){					\
		return Wrapper::NewInstance < W##className, className >(data);					\
	}

#define WRAP_NEW_INSTANCE(className)													\
	WRAP_NEW_INSTANCE_null()															\
	WRAP_NEW_INSTANCE_args()															\
	WRAP_NEW_INSTANCE_data(className)

#define WRAP_DECLARE_init(className)													\
	WRAP_constructor();																	\
	WRAP_NEW_INSTANCE(className);

#endif //!UTIL_WRAPPER_INCLUDED 

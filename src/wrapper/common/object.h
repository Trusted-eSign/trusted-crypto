#include "common.h"

#ifndef CMS_COMMON_OBJECT_H_INCLUDED
#define  CMS_COMMON_OBJECT_H_INCLUDED

#include <typeinfo>
#include <set>

class Object{
public:
	Object(){};
	virtual ~Object(){
	};

	virtual void destroy(){
	};
};

class SObject;

typedef SObject * SObjectPtr;

class SObject{
public:
	SObject(void *obj, Handle<SObject>parent, const char* tname)
		: free_(NULL), obj_(obj), type_name_(tname)
	{
		LOGGER_FN();

		this->parent = parent;
		if (!this->parent.isEmpty()){
			/*std::set < int > it;
			it.insert("");*/

			this->parent->children.insert(this);
		}
	}

	~SObject(){
		LOGGER_FN();

		if (this->isRemovable()){
			LOGGER_TRACE("OpenSSL free");
			this->free();
		}
		else
		{
			LOGGER_TRACE("Remove item from parent's children");
			this->parent->children.erase(this);
			LOGGER_TRACE("Remove children: SUCCESS");
		}
	}

	void destroy(void){
		LOGGER_FN();

		std::set<SObject*> *children = &(this->children);
		int children_size = this->children.size();
		if (children_size > 0){
			for (std::set<SObject*>::iterator i = children->begin(); i != children->end(); i++) {
				SObject *child = *i;
				child->destroy();
			}
		}
		if (this->isRemovable()){
			this->free();
		}
		this->obj_ = NULL;
		//this->parent = NULL;
	}

	template <typename N>
	N* internal(){
		LOGGER_FN();
		if (this->isEmpty())
			THROW_EXCEPTION(2, SObject, NULL, "Internal object was deleted");
		N* res = (N*)(this->obj_);
		/*
		if (!res)
			THROW_EXCEPTION(0, SObject, NULL, "Can not cast internal data");
		*/
		return res;
	}

	bool isEmpty(){
		LOGGER_FN();

		return this->obj_ == NULL;
	}

	bool isRemovable(){
		LOGGER_FN();

		bool res = this->parent.isEmpty();
		if (!res){
			res = this->parent->isEmpty();
		}
		return res;
	}

protected:
	void free(){
		LOGGER_FN();

		this->free_(this->obj_);
		this->obj_ = NULL;
	}

public:
	Handle<SObject> parent;
	void(*free_)(void *);
	std::set<SObjectPtr> children;
protected:
	void *obj_;
	const char *type_name_;

#ifdef WRAPPER_DEBUG_LOG
	std::string sslName_;
	std::string file_;
	int line;
#endif
};

template<typename T>
class SSLObject{
public:
	SSLObject(T* data, void(*fn)(void *), Handle<SObject> parent = NULL) :fnFree_(fn){
		LOGGER_TRACE("Create OpenSSL object");
		logger.write(LoggerLevel::OpenSSL, __FUNCTION__, typeid(data).name());
		this->data_ = new SObject((void *)data, parent, typeid(this).name());
		this->data_->free_ = fn;
	}

	~SSLObject(){
		//this->destroy();
	}

	void destroy(){
		LOGGER_FN();

		this->data_->destroy();
	}

	bool isEmpty(){
		LOGGER_FN();

		bool res = this->data_.isEmpty();
		if (!res)
			res = this->data_->isEmpty();
		return res;
	}

	T *internal()
	{
		LOGGER_FN();

		Handle<SObject> tmp = this->data_;
		return tmp->internal<T>();
	}

	Handle<SObject> handle(){
		LOGGER_FN();

		return this->data_;
	}

	void setParent(Handle<SObject >v){
		LOGGER_FN();

		if (!this->data_->parent.isEmpty()){
			THROW_EXCEPTION(0, SSLObject, NULL, "SSLObject has got parent.");
		}
		this->data_->parent = v;
	}

	operator T*()
	{
		return this->internal();
	}

protected:
	void setData(T* v){
		LOGGER_FN();

		//this->destroy();
		this->data_ = new SObject((void*)v, this->data_->parent, typeid(this).name());
		this->data_->free_ = fnFree_;
	}

protected:
	void(*fnFree_)(void*);
	Handle<SObject> data_;
};

#define SSLOBJECT_free(type, free_fn) \
	static void so_##type##_free(void *d){ \
	if (d != NULL) {LOGGER_TRACE("Free OpenSSL object");LOGGER_OPENSSL(#free_fn);free_fn((type*)d);}}

#define SSLOBJECT_new(class_name, type) \
	class_name(type *data, Handle<SObject> parent = NULL) \
	:SSLObject<type>(data, &so_##type##_free, parent)

#define SSLOBJECT_new_null(class_name, type, new_fn) \
	class_name() \
	:SSLObject<type>(new_fn(), &so_##type##_free)\



#endif //!CMS_COMMON_OBJECT_H_INCLUDED

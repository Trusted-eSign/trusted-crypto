#ifndef UTIL_WRAPPER_INCLUDED
#define  UTIL_WRAPPER_INCLUDED

#include <nan.h>
#include "../../wrapper/common/common.h"
#include "../helper.h"

template<typename T>
class Wrapper : public node::ObjectWrap{
private:
	typedef T childData;

		//TODO: ������� � ��� ��������� �� ����������� �������

public: 
	Handle<T> data_;
};

#define W_CLASS(type) \
	class W##type : public Wrapper<type>

#endif //!UTIL_WRAPPER_INCLUDED 

/******************************************************************************
 *                                                                             *
 *        Code from Item 29 ("Reference Counting") of MORE EFFECTIVE C++       *
 *                                                                             *
 *                               Scott Meyers                                  *
 *                                                                             *
 *            Copyright 1996 (c) Addison-Wesley Publishing Company             *
 *       You are free to use this code for non-commercial purposes only.       *
 *                                                                             *
 * This page contains the code for the classes and class templates making up   *
 * the Reference Counting Item of More Effective C++.  To use this code,       *
 * either copy this page and paste it into a C++ source file or save the       *
 * entire page as text into a C++ source file.  Don't save the HTML source     *
 * and expect that to compile :-)                                              *
 *                                                                             *
 * Each class or template in this file follows a block comment that shows the  *
 * corresponding pages in the book.  This page also contains a main function   *
 * that performs a VERY limited test of the code in this file.  You can        *
 * compile the code in this file as a stand-alone program, and you should get  *
 * this output:                                                                *
 *                                                                             *
 *     String with no changes.                                                 *
 *     String with    changes.                                                 *
 *     10                                                                      *
 *     -1                                                                      *
 *                                                                             *
 * The code here reflects all changes made to date in response to bug reports  *
 * from readers of the book.  (To see a complete list of known bugs in More    *
 * Effective C++, as well as whether they've been fixed yet, visit the         *
 * More Effective C++ Errata List.)  If you find any additional bugs, please   *
 * send them to me.                                                            *
 ******************************************************************************/

#ifndef __REF_COUNT_H__
#define __REF_COUNT_H__


#include <stdexcept>
//#include <iostream>      // The iostream facilities are not used in the classes
// in this file, but they are used in the code that
// tests the classes.

//#include <cstring>       // This includes the C string functions, e.g.,
// strlen, strcpy, etc.  They are used in the
// implementation of class String::StringValue.

// The following is for compilers that don't support bool.  Uncomment these
// lines if your compilers lack bool support.  For details on this emulation
// of bool, see More Effective C++, pp. 3-4.
// typedef int bool;
// const bool false = 0;
// const bool true = 1;

/******************************************************************************
 *                       Class RCObject (from pp. 204-205)                     *
 ******************************************************************************/
class RCObject { // base class for reference-
public: // counted objects
	void addReference();
	void removeReference();
	//void markUnshareable();
	//bool isShareable() const;
	bool isShared() const;

protected:
	RCObject();
	RCObject(const RCObject& rhs);
	RCObject& operator=(const RCObject& rhs);
	virtual ~RCObject() = 0;

private:
	int refCount;
	//bool shareable;
};

inline RCObject::RCObject()
: refCount(0) {
} //, shareable(true) {}

inline RCObject::RCObject(const RCObject&)
: refCount(0) {
} //, shareable(true) {}

inline RCObject& RCObject::operator=(const RCObject&) {
	return *this;
}

inline RCObject::~RCObject() {
}

inline void RCObject::addReference() {
	++refCount;
}

inline void RCObject::removeReference() {
	if (--refCount == 0) delete this;
}

//inline void RCObject::markUnshareable()
//{
//  shareable = false;
//}
//
//inline bool RCObject::isShareable() const
//{
//  return shareable;
//}

inline bool RCObject::isShared() const {
	return refCount > 1;
}

/******************************************************************************
 *                 Template Class RCPtr (from pp. 203, 206)                    *
 ******************************************************************************/
template<class T> // template class for smart
class RCPtr { // pointers-to-T objects; T
public: // must support the RCObject interface
	RCPtr(T* realPtr = 0);
	RCPtr(const RCPtr& rhs);
	~RCPtr();
	RCPtr& operator=(const RCPtr& rhs);
	T* operator->() const;
	T& operator*() const;

private:
	T *pointee;
	void init();
};

template<class T>
void RCPtr<T>::init() {
	if (pointee == 0) return;

	if (pointee->isShareable() == false) {
		pointee = new T(*pointee);
	}

	pointee->addReference();
}

template<class T>
RCPtr<T>::RCPtr(T* realPtr)
: pointee(realPtr) {
	init();
}

template<class T>
RCPtr<T>::RCPtr(const RCPtr& rhs)
: pointee(rhs.pointee) {
	init();
}

template<class T>
RCPtr<T>::~RCPtr() {
	if (pointee) pointee->removeReference();
}

template<class T>
RCPtr<T>& RCPtr<T>::operator=(const RCPtr& rhs) {
	if (pointee != rhs.pointee) { // this code was modified
		T *oldPointee = pointee; // for the book's 10th
		// printing
		pointee = rhs.pointee;
		init();

		if (oldPointee) oldPointee->removeReference();
	}

	return *this;
}

template<class T>
T* RCPtr<T>::operator->() const {
	return pointee;
}

template<class T>
T& RCPtr<T>::operator*() const {
	return *pointee;
}

/******************************************************************************
 *                  Template Class Handle (from pp. 209-210)                   *
 *                                                                             *
 * The code for Handle has changed over the years in response to errors        *
 * both in the original source code as well as in the subsequent fixes.  You   *
 * can find a complete list of changes at the More Effective C++ errata page.  *
 * The code here is accurate as of the 13th printing of the book.              *
 ******************************************************************************/
template<class T>
class Handle {
public:
	Handle(T* realPtr = 0);
	Handle(const Handle& rhs);
	~Handle();
	Handle& operator=(const Handle& rhs);

	T* operator->() const;
	T& operator*() const;

	RCObject& getRCObject() // give clients access to
	{
		return *counter;
	} // isShared, etc.

	T* attach(T* realPtr);
	T* detach();

	bool isEmpty() const {
		return !counter->pointee;
	}

	Handle& empty() // release()
	{
		*this = Handle(NULL);
		return *this;
	}

private:

	struct CountHolder : public RCObject {

		~CountHolder() {
			if (pointee) delete pointee;
		}
		T *pointee;
	};

	CountHolder *counter;
	void init();
};

template<class T>
void Handle<T>::init() {
	//  if (counter->isShareable() == false) {
	//    T *oldValue = counter->pointee;
	//    counter = new CountHolder;
	////    counter->pointee = oldValue ? new T(*oldValue) : 0; - not applicable for abstract classes
	//    counter->pointee = oldValue ? oldValue->clone() : 0;
	//  }

	counter->addReference();
}

template<class T>
Handle<T>::Handle(T* realPtr)
: counter(new CountHolder) {
	counter->pointee = realPtr;
	init();
}

template<class T>
Handle<T>::Handle(const Handle& rhs)
: counter(rhs.counter) {
	init();
}

template<class T>
Handle<T>::~Handle() {
	counter->removeReference();
}

template<class T>
Handle<T>& Handle<T>::operator=(const Handle& rhs) {
	if (counter != rhs.counter) {
		counter->removeReference();
		counter = rhs.counter;
		init();
	}
	return *this;
}

template<class T>
T* Handle<T>::operator->() const {
	if (!counter->pointee)
		throw std::logic_error("Pointer is NULL");

	return counter->pointee;
}

template<class T>
T& Handle<T>::operator*() const {
	if (!counter->pointee)
		throw std::logic_error("Pointer is NULL");

	return *(counter->pointee);
}

template<class T>
T* Handle<T>::attach(T* realPtr) {
	T* oldValue = counter->pointee;

	if (counter->pointee != realPtr) {
		if (!counter->isShared()) {
			counter->pointee = NULL; // it prevents releasing
		}
		*this = *new Handle(realPtr);
	}

	return oldValue;
}

template<class T>
T* Handle<T>::detach() {
	return attach(0);
}


#endif // __REF_COUNT_H__

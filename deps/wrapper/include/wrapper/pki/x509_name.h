#ifndef PKI_X509_NAME_H_INCLUDED
#define PKI_X509_NAME_H_INCLUDED

#include "pki.h"

class CTWRAPPER_API X509Name;

SSLOBJECT_free(X509_NAME, X509_NAME_free);

class X509Name : public SSLObject < X509_NAME > {
public:
	//Constructor
	SSLOBJECT_new(X509Name, X509_NAME){}
	SSLOBJECT_new_null(X509Name, X509_NAME, X509_NAME_new){}

	//Properties


	//Methods
	Handle<std::string> toString();

};

#endif  //!PKI_X509_NAME_H_INCLUDED
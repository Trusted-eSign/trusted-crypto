#ifndef CMS_SIGNER_COLLECTION_H_INCLUDED
#define  CMS_SIGNER_COLLECTION_H_INCLUDED

#include "common.h"

SSLOBJECT_free(stack_st_CMS_SignerInfo, sk_CMS_SignerInfo_free)

class SignerCollection : public SSLObject < stack_st_CMS_SignerInfo > {
public:
	//Constructor
	SSLOBJECT_new(SignerCollection, stack_st_CMS_SignerInfo){}

	//Properties
	int length();

	//Methods
	Handle<Signer> items(int index);

};

#endif  //!CMS_SIGNER_COLLECTION_H_INCLUDED


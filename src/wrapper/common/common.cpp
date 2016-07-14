#include "../stdafx.h"
#include "common.h"

#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

#include "refcount.h"
#include "excep.h"
#include "bio.h"
#include "object.h"

Handle<std::string> ASN1_TIME_toString(ASN1_TIME* time){
	if (time == NULL)
		THROW_EXCEPTION(0, Common, NULL, ERROR_PARAMETER_NULL, 1);

	LOGGER_OPENSSL(ASN1_TIME_to_generalizedtime);
	ASN1_GENERALIZEDTIME *gtime = ASN1_TIME_to_generalizedtime(time, NULL);
	Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_print);
	ASN1_GENERALIZEDTIME_print(out->internal(), gtime);
	LOGGER_OPENSSL(ASN1_GENERALIZEDTIME_free);
	ASN1_GENERALIZEDTIME_free(gtime);
	return out->read();
}

Logger logger;

std::string X509_NAME_oneline_ex(X509_NAME *a)
{
    X509_NAME_ENTRY *ne;
    std::string s("");   
    
    for (int i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++)
    {
        ne = sk_X509_NAME_ENTRY_value(a->entries, i);
        int n = OBJ_obj2nid(ne->object);
        char tmp_buf[80];
        
        std::string sn(OBJ_nid2sn(n));
        //if ((n == NID_undef) || (!sn.length()))
        //{
            int l = OBJ_obj2txt(tmp_buf, sizeof(tmp_buf), ne->object, 1);
            sn = "";
            sn += std::string(tmp_buf, l);
        //}
        s += "/"+sn+"=";    
        
        
        unsigned char *b;
        
        int b_len = ASN1_STRING_to_UTF8(&b, ne->value);
        if (b_len != -1){
            s += std::string((char *)b, b_len);
            OPENSSL_free(b);   
        }
        else{
            s += std::string((char *)ne->value->data, ne->value->length);
        }
    }
    return s;
}

ENGINE *ENGINE_CTGOST_init(){
	LOGGER_FN();

	ENGINE *e = ENGINE_CTGOST_get_ptr();
	ENGINE_register_pkey_meths(e);
	ENGINE_register_pkey_asn1_meths(e);
	return e;
}

ENGINE *ENGINE_CTGOST_get_ptr(){
	LOGGER_FN();
	ENGINE *e = ENGINE_by_id("ctgostcp");
	if (!e)
		THROW_OPENSSL_EXCEPTION(0, Common, NULL, "ENGINE 'ctgostcp' is not loaded");
	return e;
}

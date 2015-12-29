#include "../stdafx.h"
#include "common.h"

#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

#include "refcount.h"
#include "excep.h"
#include "bio.h"
#include "object.h"

/*
LPCWSTR CA2W(const char* cs, int len)
{
	if (len = -1)
		len = strlen(cs);
	wchar_t res[4096] = { 0 };
	MultiByteToWideChar(0, 0, cs, len, res, _countof(res));
	return res;
}
*/

/*
Handle<std::string> CW2A(LPCWSTR text, int len)
{
	int nLen = WideCharToMultiByte(CP_ACP, 0, text, len, NULL, 0, NULL, NULL);
	LPSTR lpszA = new CHAR[nLen];
	WideCharToMultiByte(CP_ACP, 0, text, -1, lpszA, nLen, NULL, NULL);
	Handle<std::string> res = new std::string(lpszA, nLen);
	delete[] lpszA;
	return res;
}
*/

Handle<std::string> GetLibraryPath(std::string &name){
	/*
#if !defined(CTWRAPPER_STATIC) && defined(_WIN32)
	CHAR dir_name[MAX_PATH];
	std::string full_name = std::string(LIBRARY_DIRECTORY) + name + "." + LIBRARY_EXTENSION;
	HMODULE hmodule = LoadLibrary(full_name.c_str());
	if (!hmodule){
		THROW_EXCEPTION(0, Common, NULL, "Library ''%s is not founded", full_name.c_str());
	}
	//bool mtest = GetModuleHandleEx(0, _T("ctgostcp"), &hmodule);
	bool sResultPath = GetModuleFileName(hmodule, dir_name, MAX_PATH);
	FreeLibrary(hmodule);
	if (!sResultPath){
		THROW_EXCEPTION(0, Common, NULL, "GetModuleFileName");
	}
	return new std::string(dir_name);
#else
	return new std::string("");
#endif
	*/
	return new std::string("");
}

ENGINE *ENGINE_CTGOST_init(){
	LOGGER_FN();
	//Handle<std::string> engineLib = NULL;
	//try{
	//	engineLib = GetLibraryPath(std::string("ctgostcp"));
	//}
	//catch (Handle<Exception> e){
	//	delete e;
	//	return NULL;
	//}

	//ENGINE *e = ENGINE_by_id("dynamic");

	//if (e){
	//	if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engineLib->c_str(), 0)
	//		|| !ENGINE_ctrl_cmd_string(e, "ID", "ctgostcp", 0)
	//		|| !ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0)
	//		|| !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)
	//		//|| !ENGINE_ctrl_cmd_string( e, "VERBOSE", NULL, 0 )
	//		//|| !ENGINE_ctrl_cmd_string(e, "MODULE_PATH", strPkcs11Path.c_str(), 0)
	//		//|| !ENGINE_ctrl_cmd_string( e, "PIN", "123", 0 )
	//		//|| !ENGINE_ctrl_cmd_string(e, "SKIP_FINALIZING", "1", 0)
	//		|| !ENGINE_register_pkey_meths(e)
	//		|| !ENGINE_register_pkey_asn1_meths(e)
	//		)
	//		ENGINE_free(e);

	//	if (!ENGINE_init(e))
	//		ENGINE_free(e);
	//}
	//return e;
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

ENGINE *ENGINE_CAPI_init(){
	LOGGER_FN();
	//Handle<std::string> engineLib = NULL;
	//try{
	//	engineLib = GetLibraryPath(std::string("capi"));
	//}
	//catch (Handle<Exception> e){
	//	delete e;
	//	return NULL;
	//}

	//ENGINE *e = ENGINE_by_id("dynamic");

	//if (e){
	//	if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engineLib->c_str(), 0)
	//		|| !ENGINE_ctrl_cmd_string(e, "ID", "capi", 0)
	//		|| !ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0)
	//		|| !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)
	//		//|| !ENGINE_ctrl_cmd_string( e, "VERBOSE", NULL, 0 )
	//		//|| !ENGINE_ctrl_cmd_string(e, "MODULE_PATH", strPkcs11Path.c_str(), 0)
	//		//|| !ENGINE_ctrl_cmd_string( e, "PIN", "123", 0 )
	//		//|| !ENGINE_ctrl_cmd_string(e, "SKIP_FINALIZING", "1", 0)
	//		|| !ENGINE_register_pkey_meths(e)
	//		|| !ENGINE_register_pkey_asn1_meths(e)
	//		)
	//		ENGINE_free(e);

	//	if (!ENGINE_init(e))
	//		ENGINE_free(e);
	//}
	ENGINE *e = ENGINE_CAPI_get_ptr();
	ENGINE_init(e);
	return e;
}

ENGINE *ENGINE_CAPI_get_ptr(){
	LOGGER_FN();
	return ENGINE_by_id("capi");
}

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

char *X509_NAME_onelineEx(X509_NAME *a, char *buf, int len)
{
    X509_NAME_ENTRY *ne;
    int i;
    int n, lold, l, l1, b_len;
    const char *s;
    char *p;
    unsigned char *q;
    BUF_MEM *b = NULL;
    static const char hex[17] = "0123456789ABCDEF";
    char tmp_buf[80];
#ifdef CHARSET_EBCDIC
    char ebcdic_buf[1024];
#endif

    if (buf == NULL)
    {
        if ((b = BUF_MEM_new()) == NULL) goto err;
        if (!BUF_MEM_grow(b, 200)) goto err;
        b->data[0] = '\0';
        len = 200;
    }
    if (a == NULL)
    {
        if (b)
        {
            buf = b->data;
            OPENSSL_free(b);
        }
        strncpy(buf, "NO X509_NAME", len);
        buf[len - 1] = '\0';
        return buf;
    }

    len--; /* space for '\0' */
    l = 0;
    for (i = 0; i < sk_X509_NAME_ENTRY_num(a->entries); i++)
    {
        puts("sk_X509_NAME_ENTRY_value");
        ne = sk_X509_NAME_ENTRY_value(a->entries, i);
        n = OBJ_obj2nid(ne->object);
        if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL))
        {
            i2t_ASN1_OBJECT(tmp_buf, sizeof(tmp_buf), ne->object);
            s = tmp_buf;
        }
        l1 = (int)strlen(s);

        lold = l;

        q = NULL;
        puts("ASN1_STRING_to_UTF8");
        b_len = ASN1_STRING_to_UTF8(&q, ne->value);

        l += 1 + l1 + 1 + b_len;
        if (b != NULL)
        {
            if (!BUF_MEM_grow(b, l + 1)) goto err;
            p = &(b->data[lold]);
        }
        else if (l > len)
        {
            break;
        }
        else
            p = &(buf[lold]);
        *(p++) = '/';
        memcpy(p, s, (unsigned int)l1); p += l1;
        *(p++) = '=';

        memcpy(p, q, (unsigned int)b_len); p += b_len;
    }
    *p = '\0';
    if (b != NULL)
    {
        p = b->data;
        OPENSSL_free(b);
    }
    else
        p = buf;
    return(p);
err:
    X509err(X509_F_X509_NAME_ONELINE, ERR_R_MALLOC_FAILURE);
    if (b != NULL) BUF_MEM_free(b);
    return(NULL);
}

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
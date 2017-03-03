#ifndef STOREHELPER_H_INCLUDED
#define STOREHELPER_H_INCLUDED

#include "../stdafx.h"

#include <vector>

#include "../common/common.h"

#if defined(OPENSSL_SYS_WINDOWS) 
	#define CROSSPLATFORM_SLASH       "\\"
#endif
#if defined(OPENSSL_SYS_UNIX) 
	#define CROSSPLATFORM_SLASH       "/"
#endif

class IPkiKey {
public:
	virtual ~IPkiKey(){};
public:
	bool keyEncrypted; /* Encrypted key (true or false) */
};

class IPkiCrl {
public:
	virtual ~IPkiCrl(){};
public:
	Handle<std::string> crlIssuerName;
	Handle<std::string> crlIssuerFriendlyName;
	Handle<std::string> crlLastUpdate;
	Handle<std::string> crlNextUpdate;
};

class IPkiRequest {
public:
	virtual ~IPkiRequest(){};
public:
	Handle<std::string> csrSubjectName;
	Handle<std::string>	csrSubjectFriendlyName;
	Handle<std::string> csrKey; /* thumbprint SHA1 */
};

class IPkiCertificate {
public:
	virtual ~IPkiCertificate(){};
public:
	Handle<std::string> certSubjectName;
	Handle<std::string> certSubjectFriendlyName;
	Handle<std::string> certIssuerName;
	Handle<std::string> certIssuerFriendlyName;
	Handle<std::string> certNotBefore;
	Handle<std::string> certNotAfter;
	Handle<std::string> certSerial;
	Handle<std::string> certKey; /* thumbprint SHA1 */
	Handle<std::string> certOrganizationName;
	Handle<std::string> certSignatureAlgorithm; /* thumbprint SHA1 */
};

class PkiItem : public IPkiCertificate, public IPkiCrl, public IPkiKey, public IPkiRequest{
public:
	PkiItem();
	~PkiItem(){};
public:
	Handle<std::string> format; /* DER | PEM */
	Handle<std::string> type; /* CRL | CERTIFICATE | KEY | REQUEST */
	Handle<std::string> uri; /* URI to object */
	Handle<std::string> provider; /* SYSTEM, MICROSOFT, CRYPTOPRO, TSL, PKCS11, TRUSTEDNET */
	Handle<std::string> category; /* MY, OTHERS, TRUST, CRL */
	Handle<std::string> hash; /* SHA-1 hash */
	
public:
	void setFormat(Handle<std::string> type);
	void setType(Handle<std::string> type);
	void setProvider(Handle<std::string> provider);
	void setCategory(Handle<std::string> category);
	void setURI(Handle<std::string> uri);
	void setHash(Handle<std::string> hash);
	void setSubjectName(Handle<std::string> subjectName);
	void setSubjectFriendlyName(Handle<std::string> subjectFriendlyName);
	void setIssuerName(Handle<std::string> issuerName);
	void setIssuerFriendlyName(Handle<std::string> issuerFriendlyName);
	void setSerial(Handle<std::string> serial);
	void setNotBefore(Handle<std::string> notBefore);
	void setNotAfter(Handle<std::string> notAfter);
	void setLastUpdate(Handle<std::string> lastUpdate);
	void setNextUpdate(Handle<std::string> nextUpdate);
	void setKey(Handle<std::string> keyid);
	void setKeyEncypted(bool enc);
	void setOrganizationName(Handle<std::string> organizationName);
	void setSignatureAlgorithm(Handle<std::string> signatureAlgorithm);
};

class PkiItemCollection{
public:
	PkiItemCollection();
	~PkiItemCollection();

	Handle<PkiItem> items(int index);
	int length();
	void push(Handle<PkiItem> v);
	void push(PkiItem &v);
protected:
	std::vector<PkiItem> _items;
};

class Filter {
public:
	Filter();
	~Filter(){};
public:
	void setType(Handle<std::string> type);
	void setProvider(Handle<std::string> provider);
	void setCategory(Handle<std::string> category);
	void setHash(Handle<std::string> hash);
	void setSubjectName(Handle<std::string> subjectName);
	void setSubjectFriendlyName(Handle<std::string> subjectFriendlyName);
	void setIssuerName(Handle<std::string> issuerName);
	void setIssuerFriendlyName(Handle<std::string> issuerFriendlyName);
	void setSerial(Handle<std::string> serial);
	void setIsValid(bool isValid);
public:
	std::vector<Handle<std::string> > types; /* CRL | CERTIFICATE | KEY | REQUEST (optional) */
	std::vector<Handle<std::string> > providers; /* SYSTEM, MICROSOFT, CRYPTOPRO, TSL, PKCS11, TRUSTEDNET (optional) */
	std::vector<Handle<std::string> > categorys; /* MY, OTHER, CA, TRUSTED (optional) */
	Handle<std::string> hash; /* SHA-1 hash (optional) */
	Handle<std::string> subjectName;
	Handle<std::string> subjectFriendlyName;
	Handle<std::string> issuerName;
	Handle<std::string> issuerFriendlyName;
	bool isValid;
	Handle<std::string> serial;
};

class Provider {
public:
	Provider(){};
	virtual ~Provider(){};

public:
	Handle<std::string> type;
	Handle<std::string> path; /* Only for provider system */

	Handle<PkiItemCollection> getProviderItemCollection();
	Handle<PkiItemCollection> providerItemCollection;
};

class ProviderCollection{
public:
	ProviderCollection();
	~ProviderCollection();

	Handle<Provider> items(int index);
	int length();
	void push(Handle<Provider> v);
protected:
	std::vector<Handle<Provider> > _items;
};

#endif //STOREHELPER_H_INCLUDED
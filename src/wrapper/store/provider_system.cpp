#include "../stdafx.h"

#include "provider_system.h"

#if defined(OPENSSL_SYS_WINDOWS) 
	#include <atlconv.h>
#endif

Provider_System::Provider_System(Handle<std::string> folder){
	LOGGER_FN();

	try{
		type = new std::string("SYSTEM");
		path = folder;
		providerItemCollection = new PkiItemCollection();

		if (folder.isEmpty()){
			THROW_EXCEPTION(0, Provider_System, NULL, "Dont send parameters");
		}
		else{
			init(folder);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Cannot be constructed Provider_System");
	}	
}

void Provider_System::init(Handle<std::string> folder){
#if defined(OPENSSL_SYS_UNIX) 
	DIR *dir;
	class dirent *ent;
	class stat st;
	BIO *bioFile;

	if((dir = opendir(folder->c_str())) == NULL){
		if (mkdir(folder->c_str(), 0700) != 0){
			THROW_EXCEPTION(0, Provider_System, NULL, "Error create folder");
		}
	}
	else{
		closedir(dir);
	}

	std::string listCertStore[] = {
		"MY",
		"OTHERS",
		"TRUST",
		"CRL"
	};

	for (int i = 0, c = sizeof(listCertStore) / sizeof(*listCertStore); i < c; i++){
		std::string dirInCertStore = (std::string)folder->c_str() + CROSSPLATFORM_SLASH + listCertStore[i].c_str();
		dir = opendir(dirInCertStore.c_str());
		if(dir == NULL){
			if (mkdir(dirInCertStore.c_str(), 0700) != 0){
				THROW_EXCEPTION(0, Provider_System, NULL, "Error create folder");
			}

			continue;
		}
		while ((ent = readdir(dir)) != NULL) {
			const std::string file_name = ent->d_name;
			const std::string uri = dirInCertStore + CROSSPLATFORM_SLASH +   file_name;

			if (file_name[0] == '.')
				continue;

			const bool is_directory = (st.st_mode & S_IFDIR) != 0;

			if (is_directory)
				continue;

			LOGGER_OPENSSL(BIO_new);
			bioFile = BIO_new(BIO_s_file());
			LOGGER_OPENSSL(BIO_read_filename);
			if (BIO_read_filename(bioFile, uri.c_str()) > 0){
				Handle<PkiItem> itemTemp = new PkiItem();
				itemTemp = objectToPKIItem(new std::string(uri));
				if (!itemTemp.isEmpty()){
					providerItemCollection->push(itemTemp);
				}	
			}
			LOGGER_OPENSSL(BIO_free);
			BIO_free(bioFile);
		}
		closedir(dir);
	}
#endif
#if defined(OPENSSL_SYS_WINDOWS) 
	LOGGER_FN();

	try{
		HANDLE dir;
		WIN32_FIND_DATA file_data;
		TCHAR szDir[MAX_PATH];
		BIO *bioFile;

		if ((dir = FindFirstFile(folder->c_str(), &file_data)) == INVALID_HANDLE_VALUE){
			if (_mkdir(folder->c_str()) != 0){
				THROW_EXCEPTION(0, Provider_System, NULL, "Error create folder");
			}
		}

		std::string listCertStore[] = {
			"MY",
			"OTHERS",
			"TRUST",
			"CRL"
		};

		for (int i = 0, c = sizeof(listCertStore) / sizeof(*listCertStore); i < c; i++){
			std::string dirInCertStore = (std::string)folder->c_str() + CROSSPLATFORM_SLASH + listCertStore[i].c_str();
			std::string tempdirInCertStore = "";
			tempdirInCertStore = dirInCertStore + "\\*";
			LOGGER_TRACE("FindFirstFile");
			if ((dir = FindFirstFile(tempdirInCertStore.c_str(), &file_data)) == INVALID_HANDLE_VALUE){			
				if (_mkdir(dirInCertStore.c_str()) != 0){
					THROW_EXCEPTION(0, Provider_System, NULL, "Error create folder");
				}

				continue;
			}

			do {
				std::string str = file_data.cFileName;
				std::wstring file_name(str.begin(), str.end());
				std::string uri = dirInCertStore + CROSSPLATFORM_SLASH + std::string(file_name.begin(), file_name.end());
				const bool is_directory = (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

				if (file_name[0] == '.')
					continue;

				if (is_directory)
					continue;

				LOGGER_OPENSSL(BIO_new);
				bioFile = BIO_new(BIO_s_file());
				LOGGER_OPENSSL(BIO_read_filename);
				if (BIO_read_filename(bioFile, uri.c_str()) > 0){
					Handle<PkiItem> itemTemp = new PkiItem();
					itemTemp = objectToPKIItem(new std::string(uri));
					if (!itemTemp.isEmpty()){
						providerItemCollection->push(itemTemp);
					}					
				}
			
			//	LOGGER_OPENSSL(BIO_free);
			//	BIO_free_all(bioFile);

			} while (FindNextFile(dir, &file_data));

			FindClose(dir);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Error init system store");
	}

#endif
}

Handle<PkiItem> Provider_System::objectToPKIItem(Handle<std::string> uri){
	LOGGER_FN();

	Handle<PkiItem> item;

	Handle<Bio> in =  new Bio(BIO_TYPE_FILE, uri->c_str(), "rb");

	try{
		item = new PkiItem();

		X509_REQ *xreq = NULL;
		X509 *xcert = NULL;
		X509_CRL *xcrl = NULL;

		Handle<Certificate> hcert = NULL;
		Handle<CRL> hcrl = NULL;

		std::string listCertStore[] = {
			"MY",
			"OTHERS",
			"TRUST",
			"CRL"
		};

		std::string strTrust = (uri->substr(0, (uri->find_last_of(CROSSPLATFORM_SLASH))));
		strTrust = strTrust.substr(strTrust.find_last_of(CROSSPLATFORM_SLASH) + 1, strTrust.length());

		bool trueTrust = false;
		for (int i = 0, c = sizeof(listCertStore) / sizeof(*listCertStore); i < c; i++){
			if (strcmp(listCertStore[i].c_str(), strTrust.c_str()) == 0){
				trueTrust = true;
				break;
			}
		}
		if (!trueTrust){
			THROW_EXCEPTION(0, Provider_System, NULL, "Category of object is uncorrect");
		}

		int enc;
		if (itPrivateKey(uri, &enc)){
			item->type = new std::string("KEY");
			item->uri = uri;
			item->provider = new std::string("SYSTEM");
			item->category = new std::string(strTrust);
			item->keyEncrypted = enc;
			item->format = new std::string("PEM");

			Handle<std::string> keyHash = new std::string(uri->c_str());
			const size_t last_slash_idx = keyHash->find_last_of(CROSSPLATFORM_SLASH);
			if (std::string::npos != last_slash_idx){
				keyHash->erase(0, last_slash_idx + 1);
			}
			const size_t period_idx = keyHash->rfind('.');
			if (std::string::npos != period_idx){
				keyHash->erase(period_idx);
			}
			if (keyHash->length() == 40){
				item->hash = keyHash;
			}
			else{
				THROW_EXCEPTION(0, Provider_System, NULL, "Error length hash (need 40 for sha1). Hash is privatekey filename");
			}

			return item;			
		}

		in->seek(0);

		LOGGER_OPENSSL(PEM_read_bio_X509);
		xcert = PEM_read_bio_X509(in->internal(), NULL, NULL, NULL);
		if (xcert){
			hcert = new Certificate(xcert);
			item->format = new std::string("PEM");		
		}
		else{
			in->seek(0);

			LOGGER_OPENSSL(d2i_X509_bio);
			xcert = d2i_X509_bio(in->internal(), NULL);
			if (xcert){
				hcert = new Certificate(xcert);
				item->format = new std::string("DER");
			}
		}

		if (!hcert.isEmpty()){
			item->type = new std::string("CERTIFICATE");
			item->uri = uri;
			item->provider = new std::string("SYSTEM");
			item->category = new std::string(strTrust);

			char * hexHash;
			Handle<std::string> hhash = hcert->getThumbprint();
			PkiStore::bin_to_strhex((unsigned char *)hhash->c_str(), hhash->length(), &hexHash);
			item->hash = new std::string(hexHash);

			item->certSubjectName = hcert->getSubjectName();
			item->certSubjectFriendlyName = hcert->getSubjectFriendlyName();
			item->certIssuerName = hcert->getIssuerName();
			item->certIssuerFriendlyName = hcert->getIssuerFriendlyName();
			item->certSerial = hcert->getSerialNumber();
			item->certOrganizationName = hcert->getOrganizationName();
			item->certSignatureAlgorithm = hcert->getSignatureAlgorithm();

			item->certNotBefore = hcert->getNotBefore();
			item->certNotAfter = hcert->getNotAfter();
			
			item->certKey = getKey(uri);
		
			return item;
		}

		in->seek(0);

		LOGGER_OPENSSL(PEM_read_bio_X509_REQ);
		xreq = PEM_read_bio_X509_REQ(in->internal(), NULL, NULL, NULL);
		if (xreq){
			item->format = new std::string("PEM");
		}
		else{
			in->seek(0);

			LOGGER_OPENSSL(d2i_X509_REQ_bio);
			xreq = d2i_X509_REQ_bio(in->internal(), NULL);
			if (xreq){
				item->format = new std::string("DER");
			}
		}

		if (xreq){
			item->type = new std::string("REQUEST");
			item->uri = uri;
			item->provider = new std::string("SYSTEM");
			item->category = new std::string(strTrust);

			/* SHA-1 hash */
			unsigned char hash[EVP_MAX_MD_SIZE] = { 0 };
			unsigned int hashlen = 0;
			LOGGER_OPENSSL(X509_digest);
			if (!X509_REQ_digest(xreq, EVP_sha1(), hash, &hashlen)) {
				THROW_OPENSSL_EXCEPTION(0, Provider_System, NULL, "X509_REQ_digest");
			}
			Handle<std::string> hhash = new std::string((char *)hash, hashlen);

			char * hexHash;
			PkiStore::bin_to_strhex((unsigned char *)hhash->c_str(), hhash->length(), &hexHash);
			item->hash = new std::string(hexHash);

			/* Request subject name */
			LOGGER_OPENSSL(X509_REQ_get_subject_name);
			X509_NAME *name = X509_REQ_get_subject_name(xreq);
			if (!name){
				THROW_EXCEPTION(0, Provider_System, NULL, "X509_NAME is NULL");
			}				
			LOGGER_OPENSSL(X509_NAME_oneline_ex);
			std::string str_name = X509_NAME_oneline_ex(name);
			Handle<std::string> nameRes = new std::string(str_name.c_str(), str_name.length());
			item->csrSubjectName = nameRes;

			/* Request subject friendly name */
			Handle<std::string> friendlyName = new std::string("");
			int nid = NID_commonName;
			LOGGER_OPENSSL(X509_NAME_get_index_by_NID);
			int index = X509_NAME_get_index_by_NID(name, nid, -1);
			if (index >= 0) {
				LOGGER_OPENSSL(X509_NAME_get_entry);
				X509_NAME_ENTRY *issuerNameCommonName = X509_NAME_get_entry(name, index);

				if (issuerNameCommonName) {
					LOGGER_OPENSSL(X509_NAME_ENTRY_get_data);
					ASN1_STRING *issuerCNASN1 = X509_NAME_ENTRY_get_data(issuerNameCommonName);

					if (issuerCNASN1 != NULL) {
						unsigned char *utf = NULL;
						LOGGER_OPENSSL(ASN1_STRING_to_UTF8);
						ASN1_STRING_to_UTF8(&utf, issuerCNASN1);
						friendlyName = new std::string((char *)utf);
						OPENSSL_free(utf);
					}
				}
			}
			else {
				friendlyName = new std::string("No common name");
			}
			item->csrSubjectFriendlyName = friendlyName;
			item->csrKey = getKey(uri);

			return item;
		}

		in->seek(0);

		LOGGER_OPENSSL(PEM_read_bio_X509_CRL);
		xcrl = PEM_read_bio_X509_CRL(in->internal(), NULL, NULL, NULL);
		if (xcrl){
			hcrl = new CRL(xcrl);
			item->format = new std::string("PEM");
		}
		else{
			in->seek(0);

			LOGGER_OPENSSL(d2i_X509_CRL_bio);
			xcrl = d2i_X509_CRL_bio(in->internal(), NULL);
			if (xcrl){
				hcrl = new CRL(xcrl);
				item->format = new std::string("DER");
			}
		}

		if (!hcrl.isEmpty()){
			item->type = new std::string("CRL");
			item->uri = uri;
			item->provider = new std::string("SYSTEM");			
			item->category = new std::string(strTrust);
			
			char * hexHash;
			Handle<std::string> hhash = hcrl->getThumbprint();
			PkiStore::bin_to_strhex((unsigned char *)hhash->c_str(), hhash->length(), &hexHash);
			item->hash = new std::string(hexHash);

			item->crlIssuerName = hcrl->issuerName();
			item->crlIssuerFriendlyName = hcrl->issuerFriendlyName();
			item->crlLastUpdate = hcrl->getThisUpdate();
			item->crlNextUpdate = hcrl->getNextUpdate();

			return item;
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Object type not supported");
	}

	if (item->type->length() == 0){
		return NULL;
	}
}


Handle<Certificate> Provider_System::getCertFromURI(Handle<std::string> uri, Handle<std::string> format){
	LOGGER_FN();

	try{
		BIO *bioFile = NULL;
		X509 *hcert = NULL;

		LOGGER_OPENSSL(BIO_new);
		bioFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL(BIO_read_filename);
		if (BIO_read_filename(bioFile, uri->c_str()) > 0){
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);

			if (strcmp(format->c_str(), "PEM") == 0){
				LOGGER_OPENSSL(PEM_read_bio_X509);
				hcert = PEM_read_bio_X509(bioFile, NULL, NULL, NULL);
			}
			else if (strcmp(format->c_str(), "DER") == 0){
				LOGGER_OPENSSL(d2i_X509_bio);
				hcert = d2i_X509_bio(bioFile, NULL);
			}
			else{
				THROW_EXCEPTION(0, Provider_System, NULL, "Unsupported format. Only PEM | DER");
			}
		}

		LOGGER_OPENSSL(BIO_free);
		BIO_free(bioFile);

		if (!hcert){
			THROW_EXCEPTION(0, Provider_System, NULL, "Unable decode cert from PEM/DER");
		}
		else{
			return new Certificate(hcert);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Error get certificate from URI");
	}
}

Handle<CRL> Provider_System::getCRLFromURI(Handle<std::string> uri, Handle<std::string> format){
	LOGGER_FN();

	try{
		BIO *bioFile = NULL;
		X509_CRL *hcrl = NULL;

		LOGGER_OPENSSL(BIO_new);
		bioFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL(BIO_read_filename);
		if (BIO_read_filename(bioFile, uri->c_str()) > 0){
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);

			if (strcmp(format->c_str(), "PEM") == 0){
				LOGGER_OPENSSL(PEM_read_bio_X509_CRL);
				hcrl = PEM_read_bio_X509_CRL(bioFile, NULL, NULL, NULL);
			}
			else if (strcmp(format->c_str(), "DER") == 0){
				LOGGER_OPENSSL(d2i_X509_CRL_bio);
				hcrl = d2i_X509_CRL_bio(bioFile, NULL);
			}
			else{
				THROW_EXCEPTION(0, Provider_System, NULL, "Unsupported format. Only PEM | DER");
			}
		}
		LOGGER_OPENSSL(BIO_free);
		BIO_free(bioFile);

		if (!hcrl){
			THROW_EXCEPTION(0, Provider_System, NULL, "Unable decode CRL from PEM/DE");
		}
		else{
			return new CRL(hcrl);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "getCRLFromURI");
	}
}

Handle<CertificationRequest> Provider_System::getCSRFromURI(Handle<std::string> uri, Handle<std::string> format){
	LOGGER_FN();

	try{
		BIO *bioFile = NULL;
		X509_REQ *hreq = NULL;

		LOGGER_OPENSSL(BIO_new);
		bioFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL(BIO_read_filename);
		if (BIO_read_filename(bioFile, uri->c_str()) > 0){
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);

			if (strcmp(format->c_str(), "PEM") == 0){
				LOGGER_OPENSSL(PEM_read_bio_X509_REQ);
				hreq = PEM_read_bio_X509_REQ(bioFile, NULL, NULL, NULL);
			}
			else if (strcmp(format->c_str(), "DER") == 0){
				LOGGER_OPENSSL(d2i_X509_REQ_bio);
				hreq = d2i_X509_REQ_bio(bioFile, NULL);
			}
			else{
				THROW_EXCEPTION(0, Provider_System, NULL, "Unsupported format. Only PEM | DER");
			}
		}

		LOGGER_OPENSSL(BIO_free);
		BIO_free(bioFile);

		if (!hreq){
			THROW_EXCEPTION(0, Provider_System, NULL, "Unable decode csr from PEM/DER");
		}
		else{
			return new CertificationRequest(hreq);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "getCSRFromURI");
	}
}

Handle<Key> Provider_System::getKeyFromURI(Handle<std::string> uri, Handle<std::string> format, bool enc){
	LOGGER_FN();

	try{
		if (enc){
			THROW_EXCEPTION(0, Provider_System, NULL, "Encrypted key need password callback function. Unsupported now");
		}
		BIO *bioFile = NULL;
		EVP_PKEY *hkey = NULL;

		LOGGER_OPENSSL(BIO_new);
		bioFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL(BIO_read_filename);
		if (BIO_read_filename(bioFile, uri->c_str()) > 0){
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);

			if (strcmp(format->c_str(), "PEM") == 0){
				LOGGER_OPENSSL(PEM_read_bio_PrivateKey);
				hkey = PEM_read_bio_PrivateKey(bioFile, NULL, 0, NULL);
			}
			else if (strcmp(format->c_str(), "DER") == 0){
				LOGGER_OPENSSL(d2i_PKCS8PrivateKey_bio);
				hkey = d2i_PKCS8PrivateKey_bio(bioFile, NULL, 0, NULL);
			}
			else{
				THROW_EXCEPTION(0, Provider_System, NULL, "Unsupported format. Only PEM | DER");
			}
		}

		LOGGER_OPENSSL(BIO_free);
		BIO_free(bioFile);

		if (!hkey){
			THROW_EXCEPTION(0, Provider_System, NULL, "Unable decode key from PEM/DER");
		}
		else{
			return new Key(hkey);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "getCSRFromURI");
	}
}

void Provider_System::addPkiObject(Handle<std::string> uri, Handle<Certificate> cert, unsigned int flags){
	LOGGER_FN();

	try{
		Handle<Bio> out = new Bio(BIO_TYPE_FILE, uri->c_str(), "wb");

		LOGGER_OPENSSL(PEM_write_bio_X509);
		if (!PEM_write_bio_X509(out->internal(), cert->internal())){
			THROW_OPENSSL_EXCEPTION(0, Provider_System, NULL, "PEM_write_bio_X509", NULL);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Error add certificate to store");
	}	
}

void Provider_System::addPkiObject(Handle<std::string> uri, Handle<CRL> crl, unsigned int flags){
	LOGGER_FN();

	try{
		Handle<Bio> out = new Bio(BIO_TYPE_FILE, uri->c_str(), "wb");

		LOGGER_OPENSSL(i2d_X509_CRL_bio);
		if (!i2d_X509_CRL_bio(out->internal(), crl->internal())){
			THROW_OPENSSL_EXCEPTION(0, CRL, NULL, "i2d_X509_CRL_bio");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Error add crl to store");
	}
}

void Provider_System::addPkiObject(Handle<std::string> huri, Handle<Key> key, Handle<std::string> password){
	LOGGER_FN();

	try{
		Handle<Bio> out = new Bio(BIO_TYPE_FILE, huri->c_str(), "wb");
		key->writePrivateKey(out, DataFormat::BASE64, password);
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Error add crl to store");
	}
}

void Provider_System::addPkiObject(Handle<std::string> uri, Handle<CertificationRequest> csr){
	LOGGER_FN();

	try{
		Handle<Bio> out = new Bio(BIO_TYPE_FILE, uri->c_str(), "wb");

		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if (!PEM_write_bio_X509_REQ(out->internal(), csr->internal())){
			THROW_OPENSSL_EXCEPTION(0, Provider_System, NULL, "PEM_write_bio_X509_REQ", NULL);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Error add csr to store");
	}
}

Handle<std::string> Provider_System::getKey(Handle<std::string> objectPatch){
	LOGGER_FN();

	try{
		BIO *bioKeyFile = NULL;
		Handle<std::string> key_file_name;
		size_t lastindex;

		Handle<std::string> key_hash = new std::string(objectPatch->c_str());
		const size_t last_slash_idx = key_hash->find_last_of(CROSSPLATFORM_SLASH);
		if (std::string::npos != last_slash_idx){
			key_hash->erase(0, last_slash_idx + 1);
		}
		const size_t period_idx = key_hash->rfind('.');
		if (std::string::npos != period_idx){
			key_hash->erase(period_idx);
		}
		const size_t underscore_idx = key_hash->find_last_of('_');
		if (std::string::npos != underscore_idx){
			key_hash = new std::string(key_hash->substr(underscore_idx + 1, key_hash->length()));
		}

		lastindex = objectPatch->find_last_of(CROSSPLATFORM_SLASH);
		key_file_name = new std::string(objectPatch->substr(0, lastindex) + CROSSPLATFORM_SLASH + key_hash->c_str() + ".key");
		LOGGER_OPENSSL("BIO_new");
		bioKeyFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL("BIO_read_filename");
		if (BIO_read_filename(bioKeyFile, key_file_name->c_str()) > 0){
			LOGGER_OPENSSL(bioKeyFile);
			BIO_free_all(bioKeyFile);

			const size_t last_slash_idx = key_file_name->find_last_of(CROSSPLATFORM_SLASH);
			if (std::string::npos != last_slash_idx){
				key_file_name->erase(0, last_slash_idx + 1);
			}
			const size_t period_idx = key_file_name->rfind('.');
			if (std::string::npos != period_idx){
				key_file_name->erase(period_idx);
			}

			if (key_file_name->length() == 40){
				return key_file_name;
			}
			else{
				THROW_EXCEPTION(0, Provider_System, NULL, "Error length hash (need 40 for sha1). Hash is privatekey filename");
			}
		}
		else{
			LOGGER_OPENSSL(bioKeyFile);
			BIO_free_all(bioKeyFile);

			return new std::string("");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Provider_System, e, "Error search key file");
	}	
}

bool Provider_System::itPrivateKey(Handle<std::string> uri, int *enc){
	LOGGER_FN();

	bool res = false;

	std::string symbol = "-";
	std::string privkeyHeader = "-----BEGIN PRIVATE KEY-----";
	std::string encPrivkeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
	std::string tempHeader = "-----";

	std::ifstream fileStream(uri->c_str(), std::ifstream::binary);
	fileStream.seekg(5);

	std::string line;
	std::getline(fileStream, line, symbol[0]);

	fileStream.close();

	tempHeader = tempHeader + line + "-----";

	if (strcmp(privkeyHeader.c_str(), tempHeader.c_str()) == 0){
		res = true;
		*enc = 0;
	}
	else if (strcmp(encPrivkeyHeader.c_str(), tempHeader.c_str()) == 0){
		res = true;
		*enc = 1;
	}

	return res;
}
#include "../stdafx.h"
#include "certstore.h"
#include "provider_system.h"
#include "provider_tcl.h"
#include "provider_mscrypto.h"
#include "provider_cryptopro.h"
#include "provider_pkcs11.h"
#include "provider_trustednet.h"

CertStore::CertStore(){}

/*Создание нового провайдера хранилища и занесение его в стек кэша*/
void CertStore::CERT_STORE_NEW(char* pvdType){
	if (strcmp(pvdType, "pvdTCL")==0){
		ProviderTCL* tcl = new ProviderTCL();
		cache_providers.push_back(tcl);
	}else if (strcmp(pvdType, "pvdSystem")==0){
		ProviderSystem* psys = new ProviderSystem();
		cache_providers.push_back(psys);
	}else if (strcmp(pvdType, "pvdMSCrypto")==0){
		ProviderMSCrypto* psys = new ProviderMSCrypto();
		cache_providers.push_back(psys);
	}else if (strcmp(pvdType, "pvdCryptoPro")==0){
		ProviderCryptoPRO* psys = new ProviderCryptoPRO();
		cache_providers.push_back(psys);
	}
}

void CertStore::CERT_STORE_NEW(char* pvdType, string pvdURI){
	if (strcmp(pvdType, "pvdTCL")==0){
		ProviderTCL* tcl = new ProviderTCL(pvdURI);
		cache_providers.push_back(tcl);
	}
	else if (strcmp(pvdType, "pvdSystem")==0){
		ProviderSystem* psys = new ProviderSystem(pvdURI);
		cache_providers.push_back(psys);
	}
	else if (strcmp(pvdType, "pvdMSCrypto")==0){
		ProviderMSCrypto* psys = new ProviderMSCrypto();
		cache_providers.push_back(psys);
	}
	else if (strcmp(pvdType, "pvdCryptoPro")==0){
		ProviderCryptoPRO* psys = new ProviderCryptoPRO();
		cache_providers.push_back(psys);
	}
}

void CertStore::newJSON(string *pvdURI){
	LOGGER_FN();

	try{
		Json::Value root;
		Json::Value arrayPKIobject(Json::arrayValue);
		Json::Value minParameters;

		minParameters["StoreType"] = "pvdSystem";
		minParameters["StoreURI"] = (*pvdURI).c_str();
		minParameters["PKIobject"] = arrayPKIobject;
		root["StoreSystem"] = minParameters;
		minParameters.clear();

		std::ofstream cashStore;
		cashStore.open(*pvdURI + "\\cash_cert_store.json");

		Json::StyledWriter styledWriter;
		cashStore << styledWriter.write(root);

		cashStore.close();
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, ProviderSystem, NULL, "Cannot create new json file");
	}
}
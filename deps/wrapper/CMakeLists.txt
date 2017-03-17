cmake_minimum_required(VERSION 2.8.12.2)

set (CMAKE_CXX_STANDARD 11)

project (wrapper)

set(SOURCE_LIB
	src/stdafx.cpp
	src/utils/jwt.cpp
	src/common/bio.cpp
	src/common/common.cpp
	src/common/excep.cpp
	src/common/log.cpp
	src/common/openssl.cpp
	src/common/prov.cpp
	src/pki/crl.cpp
	src/pki/crls.cpp
	src/pki/revoked.cpp
	src/pki/revokeds.cpp
	src/pki/cert.cpp
	src/pki/certs.cpp
	src/pki/key.cpp
	src/pki/cert_request_info.cpp
	src/pki/cert_request.cpp
	src/pki/csr.cpp
	src/pki/cipher.cpp
	src/pki/chain.cpp
	src/pki/pkcs12.cpp
	src/pki/revocation.cpp
	src/store/cashjson.cpp
	src/store/pkistore.cpp
	src/store/provider_system.cpp
	src/store/storehelper.cpp
	src/pki/x509_name.cpp
	src/pki/alg.cpp
	src/pki/attr.cpp
	src/pki/attrs.cpp
	src/pki/attr_vals.cpp
	src/pki/oid.cpp
	src/cms/signer.cpp
	src/cms/signer_id.cpp
	src/cms/signers.cpp
	src/cms/signer_attrs.cpp
	src/cms/signed_data.cpp
	src/cms/cmsRecipientInfo.cpp
	src/cms/cmsRecipientInfos.cpp
	jsoncpp/jsoncpp.cpp
)

add_definitions(-DOPENSSL_NO_CTGOSTCP)
add_compile_options(-std=c++11)
add_library(wrapper STATIC ${SOURCE_LIB})

include_directories(./include/)
include_directories(./jsoncpp/)


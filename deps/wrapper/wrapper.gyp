{
    "targets": [
        {
            "target_name": "wrapper",
            "type": "static_library",
            "include_dirs": ["include", "jsoncpp"],
            "sources": [
                "src/stdafx.cpp",
                "src/utils/jwt.cpp",
                "src/common/bio.cpp",
                "src/common/common.cpp",
                "src/common/excep.cpp",
                "src/common/log.cpp",
                "src/common/openssl.cpp",
                "src/common/prov.cpp",
                "src/pki/crl.cpp",
                "src/pki/crls.cpp",
                "src/pki/revoked.cpp",
                "src/pki/revokeds.cpp",
                "src/pki/cert.cpp",
                "src/pki/certs.cpp",
                "src/pki/key.cpp",
                "src/pki/cert_request_info.cpp",
                "src/pki/cert_request.cpp",
                "src/pki/csr.cpp",
                "src/pki/cipher.cpp",
                "src/pki/chain.cpp",
                "src/pki/pkcs12.cpp",
                "src/pki/revocation.cpp",
                "src/store/cashjson.cpp",
                "src/store/pkistore.cpp",
                "src/store/provider_system.cpp",
                "src/store/storehelper.cpp",
                "src/pki/x509_name.cpp",
                "src/pki/alg.cpp",
                "src/pki/attr.cpp",
                "src/pki/attrs.cpp",
                "src/pki/attr_vals.cpp",
                "src/pki/oid.cpp",
                "src/cms/signer.cpp",
                "src/cms/signer_id.cpp",
                "src/cms/signers.cpp",
                "src/cms/signer_attrs.cpp",
                "src/cms/signed_data.cpp",
                "src/cms/cmsRecipientInfo.cpp",
                "src/cms/cmsRecipientInfos.cpp",
                "jsoncpp/jsoncpp.cpp"
            ],
            "xcode_settings": {
                "OTHER_CPLUSPLUSFLAGS": [
                    "-std=c++11",
                    "-stdlib=libc++"
                ],
                "OTHER_LDFLAGS": [],
                "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
                "GCC_ENABLE_CPP_RTTI": "YES",
                "MACOSX_DEPLOYMENT_TARGET": "10.7"
            },
            "conditions": [
                [
                    "OS=='win'",
                    {
                        "sources": [
                            "src/store/provider_microsoft.cpp"
                        ],
                        "variables": {
                            "openssl_root%": "C:/openssl"
                        },
                        "link_settings": {
                            "libraries": [
                                "-l<(openssl_root)/lib/libeay32.lib",
                                "-lcrypt32.lib"
                            ],
                        },
                        "include_dirs": [
                            "<(openssl_root)/include"
                        ],
                        "defines": [ "CTWRAPPER_STATIC", "OPENSSL_NO_CTGOSTCP" ],
                        "msbuild_settings": {
                            "Link": {
                                "ImageHasSafeExceptionHandlers": "false"
                            }
                        }
                    },
                    {
                        "defines": [ "UNIX", "OPENSSL_NO_CTGOSTCP" ],

                        "cflags_cc+": [ "-std=c++11" ]
                    }
                ]
            ],
            "cflags": [ ],
            "cflags_cc!": [
                "-fno-rtti",
                "-fno-exceptions"
            ]
        }
    ]
}

{
    "targets": [
        {
            "target_name": "trusted",
            "sources": [
                "src/node/main.cpp",
                "src/node/helper.cpp",
                "src/node/stdafx.cpp",
                "src/node/utils/wlog.cpp",
                "src/node/utils/wrap.cpp",
                "src/node/pki/wcrl.cpp",
                "src/node/pki/wcrls.cpp",
                "src/node/pki/wcert.cpp",
                "src/node/pki/wcerts.cpp",
                "src/node/pki/wattr.cpp",
                "src/node/pki/wattr_vals.cpp",
                "src/node/pki/wkey.cpp",
                "src/node/pki/woid.cpp",
                "src/node/pki/walg.cpp",
                "src/node/pki/wcertRegInfo.cpp",
                "src/node/pki/wcertReg.cpp",
                "src/node/pki/wcsr.cpp",
                "src/node/pki/wcipher.cpp",
                "src/node/pki/wchain.cpp",
                "src/node/pki/wrevocation.cpp",
                "src/node/pki/wpkcs12.cpp",
                "src/node/store/wcashjson.cpp",
                "src/node/store/wpkistore.cpp",
                "src/node/store/wsystem.cpp",
                "src/node/cms/wsigned_data.cpp",
                "src/node/cms/wsigner.cpp",
                "src/node/cms/wsigners.cpp",
                "src/node/cms/wsigner_attrs.cpp",
                "src/wrapper/stdafx.cpp",
                "src/wrapper/common/bio.cpp",
                "src/wrapper/common/common.cpp",
                "src/wrapper/common/excep.cpp",
                "src/wrapper/common/log.cpp",
                "src/wrapper/common/openssl.cpp",
                "src/wrapper/common/prov.cpp",
                "src/wrapper/pki/crl.cpp",
                "src/wrapper/pki/crls.cpp",
                "src/wrapper/pki/cert.cpp",
                "src/wrapper/pki/certs.cpp",
                "src/wrapper/pki/key.cpp",
                "src/wrapper/pki/certRegInfo.cpp",
                "src/wrapper/pki/certReg.cpp",
                "src/wrapper/pki/csr.cpp",
                "src/wrapper/pki/cipher.cpp",
                "src/wrapper/pki/chain.cpp",
                "src/wrapper/pki/pkcs12.cpp",
                "src/wrapper/pki/revocation.cpp",
                "src/wrapper/store/cashjson.cpp",
                "src/wrapper/store/pkistore.cpp",
                "src/wrapper/store/provider_system.cpp",
                "src/wrapper/store/storehelper.cpp",
                "src/wrapper/pki/x509_name.cpp",
                "src/wrapper/pki/alg.cpp",
                "src/wrapper/pki/attr.cpp",
                "src/wrapper/pki/attrs.cpp",
                "src/wrapper/pki/attr_vals.cpp",
                "src/wrapper/pki/oid.cpp",
                "src/wrapper/cms/cert_id.cpp",
                "src/wrapper/cms/signer.cpp",
                "src/wrapper/cms/signers.cpp",
                "src/wrapper/cms/signer_attrs.cpp",
                "src/wrapper/cms/signed_data.cpp",
                "src/jsoncpp/jsoncpp.cpp"
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
                            "src/node/store/wmicrosoft.cpp",
                            "src/wrapper/store/provider_microsoft.cpp"
                        ],
                        "conditions": [
                            [
                                "target_arch=='x64'",
                                {
                                    "variables": {
                                        "openssl_root%": "C:/openssl"
                                    }
                                },
                                {
                                    "variables": {
                                        "openssl_root%": "C:/openssl"
                                    }
                                }
                            ]
                        ],
                        "libraries": [
                            "-l<(openssl_root)/lib/libeay32.lib",
                            "-lcrypt32.lib"
                        ],
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
                        "include_dirs": [
                            "<(node_root_dir)/deps/openssl/openssl/include"
                        ],

                        "defines": [ "UNIX", "OPENSSL_NO_CTGOSTCP" ],

                        "cflags_cc+": [ "-std=c++11" ]
                    }
                ]
            ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            "cflags": [ ],
            "cflags_cc!": [
                "-fno-rtti",
                "-fno-exceptions"
            ]
        }
    ]
}

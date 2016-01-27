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
                "src/node/pki/wcert.cpp",
                "src/node/pki/wcerts.cpp",
                "src/node/pki/wattr.cpp",
                "src/node/pki/wattr_vals.cpp",
                "src/node/pki/wkey.cpp",
                "src/node/pki/woid.cpp",
                "src/node/pki/walg.cpp",
                "src/node/certstore/wcertstore.cpp",
                "src/node/certstore/wprovider_system.cpp",
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
                "src/wrapper/pki/cert.cpp",
                "src/wrapper/pki/certs.cpp",
                "src/wrapper/pki/key.cpp",
                "src/wrapper/certstore/certstore.cpp",
                "src/wrapper/certstore/provider_system.cpp",
                "src/wrapper/certstore/provider_tcl.cpp",
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
            "conditions": [
                [
                    "OS=='win'",
                    {
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
                            "-l<(openssl_root)/lib/libeay32.lib"
                        ],
                        "include_dirs": [
                            "<(openssl_root)/include"
                        ],
                        "defines": [ "CTWRAPPER_STATIC" ],
                        "msbuild_settings": {
                            "Link": {
                                "ImageHasSafeExceptionHandlers": "false"
                            }
                        }
                    },
                    {
                        "libraries": [
                            "-luuid"
                        ],

                        "include_dirs": [
                            "<(node_root_dir)/deps/openssl/openssl/include"
                        ]
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
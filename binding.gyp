{
    "targets": [
        {
            "target_name": "trusted",
            "dependencies": [
                "deps/wrapper/wrapper.gyp:wrapper",
            ],
            "sources": [
                "src/node/main.cpp",
                "src/node/helper.cpp",
                "src/node/stdafx.cpp",
                "src/node/common/wopenssl.cpp",
                "src/node/utils/wlog.cpp",
                "src/node/utils/wrap.cpp",
                "src/node/utils/wjwt.cpp",
                "src/node/utils/wcsp.cpp",
                "src/node/pki/wcrl.cpp",
                "src/node/pki/wcrls.cpp",
                "src/node/pki/wrevoked.cpp",
                "src/node/pki/wrevokeds.cpp",
                "src/node/pki/wcert.cpp",
                "src/node/pki/wcerts.cpp",
                "src/node/pki/wattr.cpp",
                "src/node/pki/wattr_vals.cpp",
                "src/node/pki/wkey.cpp",
                "src/node/pki/woid.cpp",
                "src/node/pki/walg.cpp",
                "src/node/pki/wcert_request_info.cpp",
                "src/node/pki/wcert_request.cpp",
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
                "src/node/cms/wsigner_id.cpp",
                "src/node/cms/wsigners.cpp",
                "src/node/cms/wsigner_attrs.cpp",
                "src/node/cms/wcmsRecipientInfo.cpp",
                "src/node/cms/wcmsRecipientInfos.cpp"
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
                            "src/node/store/wmicrosoft.cpp"
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
                            "-l<(module_root_dir)/build/Release/wrapper.lib",
                            "-l<(openssl_root)/lib/libeay32.lib",
                            "-lcrypt32.lib"
                        ],
                        "include_dirs": [
                            "<(openssl_root)/include",
                            "deps/wrapper/include",
                            "deps/wrapper/jsoncpp"
                        ],
                        "defines": ["CTWRAPPER_STATIC", "OPENSSL_NO_CTGOSTCP", "JWT_NO_LICENSE"],
                        "msbuild_settings": {
                            "Link": {
                                "ImageHasSafeExceptionHandlers": "false"
                            }
                        }
                    },
                    {
                        "conditions": [
                            ['OS=="linux"', {
                                "libraries": [
                                    "-lcrypto"
                                ]
                            }]],
                        "libraries": [
                            "-L<(module_root_dir)/build/Release/wrapper.a"
                        ],
                        "include_dirs": [
                            "deps/wrapper/include",
                            "deps/wrapper/jsoncpp"
                        ],

                        "defines": ["UNIX", "OPENSSL_NO_CTGOSTCP", "JWT_NO_LICENSE"],

                        "cflags_cc+": ["-std=c++11"]
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

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
                "src/wrapper/stdafx.cpp",
                "src/wrapper/common/bio.cpp",
                "src/wrapper/common/common.cpp",
                "src/wrapper/common/excep.cpp",
                "src/wrapper/common/log.cpp",
                "src/wrapper/common/openssl.cpp",
                "src/wrapper/common/prov.cpp",
                "src/wrapper/pki/crl.cpp",
                "src/wrapper/pki/cert.cpp"
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
                                        "openssl_root%": "C:/OpenSSL-Win64"
                                    }
                                },
                                {
                                    "variables": {
                                        "openssl_root%": "C:/OpenSSL-Win32"
                                    }
                                }
                            ]
                        ],
                        "libraries": [
                            "-l<(openssl_root)/lib/libeay32.lib"
                        ],
                        "include_dirs": [
                            "<(openssl_root)/include"
                        ]
                    },
                    {
                        "include_dirs": [
                            "<!(node -e \"require('nan')\")",
                            "<(node_root_dir)/deps/openssl/openssl/include"
                        ]
                    }
                ]
            ],
            "cflags": [],
            "cflags_cc!": [
                "-fno-rtti",
                "-fno-exceptions"
            ]
        }
    ]
}
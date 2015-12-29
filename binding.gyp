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
			"include_dirs": [
				"<!(node -e \"require('nan')\")",
				"<(node_root_dir)/deps/openssl/openssl/include"
			],
			"cflags": [],
			"cflags_cc!": [
				"-fno-rtti",
				"-fno-exceptions"
			]
		}
	]
}
var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";

describe('CertStore', function () {
	var certstore;

	it('init', function () {
		certstore = new trusted.pki.CertStore()
		assert.equal(certstore != null, true);
	})
	
	it('addCertStore', function () {
		certstore.addCertStore("pvdSystem", DEFAULT_CERTSTORE_PATH);
    });

    it('createCache', function () {
		certstore.createCache("test/CertStore/cash_cert_store.json");
    });
	
	it('addCacheSection', function () {
		certstore.addCacheSection("test/CertStore/cash_cert_store.json", "pvdSystem");
    });
	
	it('params before delete system provider', function () {
        console.log("listCertStore:", certstore.listCertStore);
		console.log("prvSystem load:", certstore.getPrvTypePresent("pvdSystem"));
    });
	
	it('removeCertStore', function () {
		certstore.removeCertStore("pvdSystem");
    });
	
	it('params after delete system provider', function () {
        console.log("listCertStore:", certstore.listCertStore);
		console.log("prvSystem load:", certstore.getPrvTypePresent("pvdSystem"));
    });
});

describe('Key', function () {
	var key;

	it('init', function () {
		key = new trusted.pki.Key()
		assert.equal(key != null, true);
	})

    it('keypairGenerate', function () {
		key.keypairGenerate(DEFAULT_CERTSTORE_PATH+"/MY/privkey.key", 1, 1024, "");
    });
	
	it('keypairGenerateMemory', function () {
		key.keypairGenerateMemory(1, 1024, "");
    });
	
	it('keypairGenerateBIO', function () {
		key.keypairGenerateBIO(1, 1024, "");
    });
	
	it('privkeyLoad', function () {
		key.privkeyLoad(DEFAULT_CERTSTORE_PATH+"/MY/privkey.key", 1, "");
    });
	
	it('privkeySave', function () {
		key.privkeySave(DEFAULT_CERTSTORE_PATH+"/MY/privkey_s.key", 1, "");
    });
	
	it('pubkeySave', function () {
		key.pubkeySave(DEFAULT_CERTSTORE_PATH+"/MY/pubkey_s.key", 1);
    });
	
	it('pubkeyLoad', function () {
		key.pubkeyLoad(DEFAULT_CERTSTORE_PATH+"/MY/pubkey_s.key", 1);
    });
});
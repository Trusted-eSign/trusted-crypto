var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";

describe('CertStore', function () {
	var certstore;

	it('init', function () {
		certstore = new trusted.Pki.CertStore()
		assert.equal(certstore != null, true);
	})

   /* it('newJson', function () {
		certstore.newJson(DEFAULT_CERTSTORE_PATH);
    });*/
});

describe('Key', function () {
	var key;

	it('init', function () {
		key = new trusted.Pki.Key()
		assert.equal(key != null, true);
	})

    it('keypairGenerate', function () {
		key.keypairGenerate(DEFAULT_CERTSTORE_PATH+"/MY/privkey.key", 1, 1024, "1234");
    });
	
	it('keypairGenerateMemory', function () {
		key.keypairGenerateMemory(1, 1024, "1234");
    });
	
	it('keypairGenerateBIO', function () {
		key.keypairGenerateBIO(1, 1024, "1234");
    });
	
	it('privkeyLoad', function () {
		key.privkeyLoad(DEFAULT_CERTSTORE_PATH+"/MY/privkey.key", 1, "1234");
    });
	
	it('privkeySave', function () {
		key.privkeySave(DEFAULT_CERTSTORE_PATH+"/MY/privkey_s.key", 1, "1234");
    });
	
	it('pubkeyLoad', function () {
		key.pubkeyLoad(DEFAULT_CERTSTORE_PATH+"/MY/pubkey.key", 1);
    });
	
	it('pubkeySave', function () {
		key.pubkeySave(DEFAULT_CERTSTORE_PATH+"/MY/pubkey_s.key", 1);
    });
});
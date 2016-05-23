var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";
var OUT_PATH = "test";

describe('Key', function () {
	var key;

	it('init', function () {
		key = new trusted.pki.Key()
		assert.equal(key != null, true);
	})

  it('keypairGenerate', function () {
		key.keypairGenerate(OUT_PATH + "/privkey.key", trusted.DataFormat.PEM, trusted.PublicExponent.RSA_F4, 1024, "1234");
  });
	
	it('keypairGenerateMemory', function () {
		key.keypairGenerateMemory(trusted.DataFormat.PEM, trusted.PublicExponent.RSA_F4, 1024, "");
  });
	
	it('keypairGenerateBIO', function () {
		key.keypairGenerateBIO(trusted.DataFormat.PEM, trusted.PublicExponent.RSA_F4, 1024, "");
  });
	
	it('privkeyLoad', function () {
		key.privkeyLoad(OUT_PATH + "/privkey.key", trusted.DataFormat.PEM, "1234");
		assert.equal(key != null, true);
  });
	
	it('privkeySave', function () {
		key.privkeySave(OUT_PATH + "/privkey_s.key", trusted.DataFormat.PEM, "");
  });
	
	it('pubkeySave', function () {
		key.pubkeySave(OUT_PATH + "/pubkey_s.key", trusted.DataFormat.PEM);
  });
	
	it('pubkeyLoad', function () {
		key.pubkeyLoad(OUT_PATH + "/pubkey_s.key", trusted.DataFormat.PEM);
		assert.equal(key != null, true);
  });
});

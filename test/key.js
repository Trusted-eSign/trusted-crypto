var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";
var OUT_PATH = "test";

describe('Key', function () {
	var key, privateKey;
	var keyPair;

	it('init', function () {
		key = new trusted.pki.Key()
		assert.equal(key != null, true);
	})

  it('generate', function () {
		keyPair = key.generate(trusted.DataFormat.PEM, trusted.PublicExponent.RSA_F4, 1024);
  });

	it('save private', function () {
		keyPair.writePrivateKey(OUT_PATH + "/privkey_s.key", trusted.DataFormat.PEM, "1234");
  });
		
	it('read private', function () {
		privateKey = key.readPrivateKey(OUT_PATH + "/privkey_s.key", trusted.DataFormat.PEM, "1234");
		assert.equal(privateKey != null, true);
  });
		
	it('save public', function () {
		key.writePublicKey(OUT_PATH + "/pubkey_s.key", trusted.DataFormat.PEM);
  });
	
	it('read public', function () {
		key.readPublicKey(OUT_PATH + "/pubkey_s.key", trusted.DataFormat.PEM);
		assert.equal(key != null, true);
  });
});

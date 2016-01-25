var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";

describe('ProviderSystem', function () {
	var providersystem;

	it('init', function () {
		providersystem = new trusted.Pki.ProviderSystem(DEFAULT_CERTSTORE_PATH)
		assert.equal(providersystem != null, true);
	})

   it('fillingJsonFromSystemStore', function () {
		providersystem.fillingJsonFromSystemStore(DEFAULT_CERTSTORE_PATH);
    });
	
	it('readJson', function () {
		console.log("JSON:",providersystem.readJson(DEFAULT_CERTSTORE_PATH + "/cash_cert_store.json"));
    });
});
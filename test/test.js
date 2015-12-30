var assert = require('assert');
var trusted = require("../index.js")

describe('CRL', function () {
	var crl;

	it('init', function () {
		crl = new trusted.Pki.Crl()
		assert.equal(crl != null, true);
	})

    it('load', function () {
		crl.load("test/test.crl");
    });

	it('params', function () {
		assert.equal(crl.version, 1, "Bad version value")
		assert.equal(typeof (crl.issuerName), "string", "Bad issuerName value")
		assert.equal(typeof (crl.lastUpdate), "object", "Bad lastUpdate value")
		assert.equal(typeof (crl.nextUpdate), "object", "Bad nextUpdate value")
	})

	it('export', function () {
		var buf = crl.export();
		assert.equal(Buffer.isBuffer(buf), true);
	})

});

describe('Certificate', function () {
	var cert;

	it('init', function () {
		console.log(trusted.Pki);
		cert = new trusted.Pki.Certificate()
		assert.equal(cert != null, true);
	})

    it('load', function () {
		cert.load("test/test.crt");
    });

	it('params', function () {
		/*
		assert.equal(cert.version, 1, "Bad version value")
		assert.equal(typeof (cert.issuerName), "string", "Bad issuerName value")
		assert.equal(typeof (cert.lastUpdate), "object", "Bad lastUpdate value")
		assert.equal(typeof (cert.nextUpdate), "object", "Bad nextUpdate value")
        */
		
		console.log("scn:",cert.subjectFriendlyName);
		console.log("icn:",cert.issuerFriendlyName);
		console.log("sn:",cert.subjectName);
		console.log("in:",cert.issuerName);
		console.log("nBefore:",cert.notBefore);
		console.log("nAfter:",cert.notAfter);
		console.log("serialNumber:",cert.serialNumber.toString('hex'));
		console.log("thumbprint:",cert.thumbprint.toString('hex'));
		console.log("version:",cert.version);
		console.log("type:",cert.type);
		console.log("keyUsage:",cert.keyUsage);
        
	})
    
    it('ru', function () {
		/*
		assert.equal(cert.version, 1, "Bad version value")
		assert.equal(typeof (cert.issuerName), "string", "Bad issuerName value")
		assert.equal(typeof (cert.lastUpdate), "object", "Bad lastUpdate value")
		assert.equal(typeof (cert.nextUpdate), "object", "Bad nextUpdate value")
        */
		var c = trusted.Pki.Certificate.load("test/test-ru.crt");
		console.log("scn:",c.subjectFriendlyName);
		console.log("sn:",c.subjectName);
        //var n = c.subjectName;
	})

	it('export', function () {
		var buf = cert.export();
		assert.equal(Buffer.isBuffer(buf), true);
		console.log("Export", buf.toString('hex'));
	})

});

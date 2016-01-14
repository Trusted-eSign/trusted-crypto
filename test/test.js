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

        console.log("scn:", cert.subjectFriendlyName);
        console.log("icn:", cert.issuerFriendlyName);
        console.log("sn:", cert.subjectName);
        console.log("in:", cert.issuerName);
        console.log("nBefore:", cert.notBefore);
        console.log("nAfter:", cert.notAfter);
        console.log("serialNumber:", cert.serialNumber.toString('hex'));
        console.log("thumbprint:", cert.thumbprint.toString('hex'));
        console.log("version:", cert.version);
        console.log("type:", cert.type);
        console.log("keyUsage:", cert.keyUsage);

    })

    it('ru', function () {
		/*
		assert.equal(cert.version, 1, "Bad version value")
		assert.equal(typeof (cert.issuerName), "string", "Bad issuerName value")
		assert.equal(typeof (cert.lastUpdate), "object", "Bad lastUpdate value")
		assert.equal(typeof (cert.nextUpdate), "object", "Bad nextUpdate value")
        */
        var c = trusted.Pki.Certificate.load("test/test-ru.crt");
        console.log("scn:", c.subjectFriendlyName);
        console.log("sn:", c.subjectName);
        //var n = c.subjectName;
    })

    it('export PEM', function () {
        var buf = cert.export(trusted.DataFormat.PEM);
        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, false);
    })

    it('export Default', function () {
        var buf = cert.export();
        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    })

    it('export DER', function () {
        var buf = cert.export(trusted.DataFormat.DER);
        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    })

    it("duplicate", function () {
        var cert1 = trusted.Pki.Certificate.load("test/test.crt");
        var cert2 = cert1.duplicate();
        assert.equal(cert1.thumbprint === cert2.thumbprint, true, "Certificates are not equals");
    })

    it("equals", function () {
        var cert1 = trusted.Pki.Certificate.load("test/test.crt");
        var cert2 = trusted.Pki.Certificate.load("test/test-ru.crt");
        var cert3 = trusted.Pki.Certificate.load("test/test.crt");
        assert.equal(cert1.equals(cert2), false, "Certificates are equals");
        assert.equal(cert1.equals(cert3), true, "Certificates are not equals");
    })

    it("compare", function () {
        var cert1 = trusted.Pki.Certificate.load("test/test.crt");
        var cert2 = trusted.Pki.Certificate.load("test/test-ru.crt");
        assert.equal(cert1.compare(cert2), 1, "Wrong compare");
        assert.equal(cert2.compare(cert1), -1, "Wrong compare");
        assert.equal(cert1.compare(cert1), 0, "Wrong compare");
    })

    it("hash", function () {
        var cert1 = trusted.Pki.Certificate.load("test/test.crt");

        var hash1 = cert1.hash();
        var hash2 = cert1.hash("sha1");
        var hash3 = cert1.hash("sha256");

        assert.equal(hash1.length, 40, "Длина хеш SHA1 должна быть 20");
        assert.equal(hash2.length, 40, "Длина хеш SHA1 должна быть 20");
        assert.equal(hash3.length, 64, "Длина хеш SHA1 должна быть 32");

        assert.equal(hash1 === hash2, true, "Значения хеш не совпадают");

    })

});

describe('OID', function () {
    it("create", function () {
        var oid = new trusted.Pki.Oid("2.5.4.3");
        assert.equal(oid.value, "2.5.4.3");
        assert.equal(oid.longName, "commonName");
        assert.equal(oid.shortName, "CN");
    })

    it("create with error", function () {
        assert.throws(function () {
            new trusted.Pki.Oid("2.5.4.3_error");
        });
    })
})

describe('Algorithm', function () {
    it("create", function () {
        var alg = new trusted.Pki.Algorithm("SHA");
        assert.equal(alg.typeId.shortName, "SHA");
        assert.equal(alg.name, "sha");
        assert.equal(alg.duplicate().name, "sha");
        assert.equal(alg.compare(new trusted.Pki.Algorithm("SHA256")), -1);
        assert.equal(alg.isDigest(), true);
    })

    it("create with error", function () {
        assert.throws(function () {
            new trusted.Pki.Algorithm("SHA123_error")
        });
    })
})
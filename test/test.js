var assert = require('assert');
var trusted = require("../index.js")
var fs = require("fs");

describe('CRL', function () {
    var crl;

    it('init', function () {
        crl = new trusted.pki.Crl()
        assert.equal(crl != null, true);
    })

    it('load', function () {
        crl.load("test/test.crl");
    });

    it('params', function () {
		assert.equal(typeof (crl.encoded), "string", "Bad encoded value")
		assert.equal(typeof (crl.signature), "string", "Bad signature value")
		
		console.log("version:", crl.version);
		console.log("SHA-1 hash:", crl.thumbprint);
		console.log("Signature algorithm long name:", crl.sigAlgName);
		console.log("Signature algorithm short name:", crl.sigAlgShortName);
		console.log("Signature algorithm OID:", crl.sigAlgOID);
		console.log("Issuer name:", crl.issuerName);
		console.log("Last update:", crl.lastUpdate);
		console.log("Next update:", crl.nextUpdate);
		
      /*assert.equal(typeof (crl.issuerName), "string", "Bad issuerName value")
        assert.equal(typeof (crl.lastUpdate), "object", "Bad lastUpdate value")
        assert.equal(typeof (crl.nextUpdate), "object", "Bad nextUpdate value")*/
    })

    it('export', function () {
        var buf = crl.export();
        assert.equal(Buffer.isBuffer(buf), true);
    })
	
	it("duplicate", function () {
        var crl1 = trusted.pki.Crl.load("test/test.crl");
        var crl2 = crl1.duplicate();
		assert.equal(crl1.thumbprint === crl2.thumbprint, true, "CRL are not equals");
    })
	
	it("equals", function () {
        var crl1 = trusted.pki.Crl.load("test/CertStore/CRL/ThawteCSG2.crl");
        var crl2 = trusted.pki.Crl.load("test/CertStore/CRL/ThawtePCA.crl");
        assert.equal(crl1.equals(crl1), 0, "CRL are equals");
		assert.equal(crl1.equals(crl2), -1, "CRL are not equals");
    })
	
	it("hash", function () {
        var crl1 = trusted.pki.Crl.load("test/test.crl");

        var hash1 = crl1.hash();
        var hash2 = crl1.hash("sha1");
        var hash3 = crl1.hash("sha256");

        assert.equal(hash1.length, 40, "Длина хеш SHA1 должна быть 20");
        assert.equal(hash2.length, 40, "Длина хеш SHA1 должна быть 20");
        assert.equal(hash3.length, 64, "Длина хеш SHA1 должна быть 32");

        assert.equal(hash1 === hash2, true, "Значения хеш не совпадают");

    })
	
	it("revoked", function () {
        var crl1 = trusted.pki.Crl.load("test/test.crl");
		crl1.getRevokedCertificateCert(trusted.pki.Certificate.load("test/test.crt"));
    })
	
});

describe('Certificate', function () {
    var cert;

    it('init', function () {
        cert = new trusted.pki.Certificate()
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
        var c = trusted.pki.Certificate.load("test/test-ru.crt");
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
        var cert1 = trusted.pki.Certificate.load("test/test.crt");
        var cert2 = cert1.duplicate();
        assert.equal(cert1.thumbprint === cert2.thumbprint, true, "Certificates are not equals");
    })

    it("equals", function () {
        var cert1 = trusted.pki.Certificate.load("test/test.crt");
        var cert2 = trusted.pki.Certificate.load("test/test-ru.crt");
        var cert3 = trusted.pki.Certificate.load("test/test.crt");
        assert.equal(cert1.equals(cert2), false, "Certificates are equals");
        assert.equal(cert1.equals(cert3), true, "Certificates are not equals");
    })

    it("compare", function () {
        var cert1 = trusted.pki.Certificate.load("test/test.crt");
        var cert2 = trusted.pki.Certificate.load("test/test-ru.crt");
        assert.equal(cert1.compare(cert2), 1, "Wrong compare");
        assert.equal(cert2.compare(cert1), -1, "Wrong compare");
        assert.equal(cert1.compare(cert1), 0, "Wrong compare");
    })

    it("hash", function () {
        var cert1 = trusted.pki.Certificate.load("test/test.crt");

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
        var oid = new trusted.pki.Oid("2.5.4.3");
        assert.equal(oid.value, "2.5.4.3");
        assert.equal(oid.longName, "commonName");
        assert.equal(oid.shortName, "CN");
    })

    it("create with error", function () {
        assert.throws(function () {
            new trusted.pki.Oid("2.5.4.3_error");
        });
    })
})

describe('Algorithm', function () {
    it("create", function () {
        var alg = new trusted.pki.Algorithm("SHA");
        assert.equal(alg.typeId.shortName, "SHA");
        assert.equal(alg.name, "sha");
        assert.equal(alg.duplicate().name, "sha");
        assert.equal(alg.isDigest(), true);
    })

    it("create with error", function () {
        assert.throws(function () {
            new trusted.pki.Algorithm("SHA123_error")
        });
    })
})

describe('SignedData', function () {
    it("load", function () {
        var cms = new trusted.cms.SignedData();
        cms.load("test/test02.txt.sig");
        
        var signers = cms.signers;
        for (var i in signers){
            var signer = signers[i];
            console.log(signer.digestAlgorithm.name);
        }
        
        var certs = cms.certificates;
        for (var i in certs){
            var cert = certs[i];
            console.log(cert.subjectName);
        }
        console.log("isDetached:", cms.isDetached());
    })
})

describe('CertificateCollection', function () {    
    it("push", function () {
        var certs = new trusted.pki.CertificateCollection();
        
        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load("test/test.crt"));
        assert.equal(certs.length, 1);
        certs.push(trusted.pki.Certificate.load("test/test.crt"));
        assert.equal(certs.length, 2);
    })
    
    it("remove", function () {
        var certs = new trusted.pki.CertificateCollection();
        
        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load("test/test.crt"));
        assert.equal(certs.length, 1);
        certs.push(trusted.pki.Certificate.load("test/test.crt"));
        assert.equal(certs.length, 2);
        certs.pop();
        assert.equal(certs.length, 1);
        certs.removeAt(0);
        assert.equal(certs.length, 0);
    })
    
    it("items", function () {
        var certs = new trusted.pki.CertificateCollection();
        
        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load("test/test.crt"));
        assert.equal(certs.length, 1);
        var cert = certs.items(0);
        assert.equal(cert.version, 2);  
    })
})
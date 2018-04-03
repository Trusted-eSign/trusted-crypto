"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("Certificate", function() {
    var cert;
    var exts;

    it("init", function() {
        var ext1;
        var ext2;
        var oid;

        cert = new trusted.pki.Certificate();
        assert.equal(cert !== null, true);

        oid = new trusted.pki.Oid("keyUsage");
        assert.equal(oid !== null, true);

        ext1 = new trusted.pki.Extension(oid, "critical,digitalSignature,keyEncipherment");
        assert.equal(ext1 !== null, true);

        oid = new trusted.pki.Oid("subjectAltName");
        assert.equal(oid !== null, true);

        ext2 = new trusted.pki.Extension(oid, "email:test@example.com");
        assert.equal(ext2 !== null, true);

        exts = new trusted.pki.ExtensionCollection();
        assert.equal(exts !== null, true);

        assert.equal(exts.length, 0);
        exts.push(ext1);
        assert.equal(exts.length, 1);
        exts.push(ext2);
        assert.equal(exts.length, 2);
    });

    it("load", function() {
        cert.load(DEFAULT_RESOURCES_PATH + "/test.crt");
    });

    it("params", function() {
        assert.equal(cert.version, 2, "Bad version value");
        assert.equal(typeof (cert.subjectFriendlyName), "string", "Bad subjectFriendlyName value");
        assert.equal(typeof (cert.issuerFriendlyName), "string", "Bad issuerFriendlyName value");
        assert.equal(typeof (cert.subjectName), "string", "Bad subjectName value");
        assert.equal(typeof (cert.issuerName), "string", "Bad issuerName value");
        assert.equal(typeof (cert.notAfter), "object", "Bad notAfter value");
        assert.equal(typeof (cert.notBefore), "object", "Bad notBefore value");
        assert.equal(typeof (cert.serialNumber), "string", "Bad serialNumber value");
        assert.equal(typeof (cert.thumbprint), "string", "Bad thumbprint value");
        assert.equal(typeof (cert.type), "number", "Bad type value");
        assert.equal(typeof (cert.keyUsage), "number", "Bad keyUsage value");
        assert.equal(typeof (cert.signatureAlgorithm), "string", "Bad signatureAlgorithm value");
        assert.equal(typeof (cert.signatureDigestAlgorithm), "string", "Bad signatureDigestAlgorithm value");
        assert.equal(typeof (cert.publicKeyAlgorithm), "string", "Bad publicKeyAlgorithm value");
        assert.equal(typeof (cert.organizationName), "string", "Bad organizationName value");
        assert.equal(typeof (cert.OCSPUrls), "object", "Bad OCSPUrls value");
        assert.equal(cert.OCSPUrls.length, 1, "Bad OCSP urls length");
        assert.equal(typeof (cert.CAIssuersUrls), "object", "Bad CA Issuers value");
        assert.equal(cert.CAIssuersUrls.length, 1, "Bad CA Issuers urls length");
        assert.equal(cert.extensions.length, 7, "Bad extensions length");
        assert.equal(typeof (cert.isSelfSigned), "boolean", "Error check self signed");
        assert.equal(typeof (cert.isCA), "boolean", "Error check CA");
    });

    it("ru", function() {
        var ruCert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.crt");

        assert.equal(ruCert.version, 2, "Bad version value");
        assert.equal(typeof (ruCert.subjectFriendlyName), "string", "Bad subjectFriendlyName value");
        assert.equal(typeof (ruCert.subjectName), "string", "Bad subjectName value");
    });

    it("export PEM", function() {
        var buf = cert.export(trusted.DataFormat.PEM);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, false);
    });

    it("export Default", function() {
        var buf = cert.export();

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("export DER", function() {
        var buf = cert.export(trusted.DataFormat.DER);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CERTIFICATE-----") === -1, true);
    });

    it("duplicate", function() {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt");
        cert2 = cert1.duplicate();
        assert.equal(cert1.thumbprint === cert2.thumbprint, true, "Certificates are not equals");
    });

    it("equals", function() {
        var cert1, cert2, cert3;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt");
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.crt");
        cert3 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt");
        assert.equal(cert1.equals(cert2), false, "Certificates are equals");
        assert.equal(cert1.equals(cert3), true, "Certificates are not equals");
    });

    it("compare", function() {
        var cert1, cert2;

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt");
        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.crt");
        assert.equal(cert1.compare(cert2), 1, "Wrong compare");
        assert.equal(cert2.compare(cert1), -1, "Wrong compare");
        assert.equal(cert1.compare(cert1), 0, "Wrong compare");
    });

    it("hash", function() {
        var cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt");

        var hash1 = cert1.hash();
        var hash2 = cert1.hash("sha1");
        var hash3 = cert1.hash("sha256");

        assert.equal(hash1.length, 40, "SHA1 length 40");
        assert.equal(hash2.length, 40, "SHA1 length 40");
        assert.equal(hash3.length, 64, "SHA256 length 64");

        assert.equal(hash1 === hash2, true, "Hashes are not equals");
    });

    it("create from csr", function() {
        var cert1;
        var req = new trusted.pki.CertificationRequest();

        req.load(DEFAULT_RESOURCES_PATH + "/testreq.pem", trusted.DataFormat.PEM);

        cert1 = new trusted.pki.Certificate(req);
        assert.equal(cert1 !== null, true);

        cert1.subjectName = cert.subjectName;
        assert.equal(typeof (cert1.subjectName), "string", "Bad subjectName value");

        cert1.issuerName = cert.issuerName;
        assert.equal(typeof (cert1.issuerName), "string", "Bad subjectName value");

        cert1.version = 2;
        assert.equal(typeof (cert1.version), "number", "Bad version value");

        cert1.extensions = exts;
        assert.equal(typeof (cert1.extensions), "object", "Bad extensions value");

        cert1.serialNumber = "";
        assert.equal(typeof (cert1.serialNumber), "object", "Bad extensions value");
    });
});

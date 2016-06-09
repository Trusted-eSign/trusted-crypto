"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("Certificate", function() {
    var cert;

    it("init", function() {
        cert = new trusted.pki.Certificate();
        assert.equal(cert !== null, true);
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
        assert.equal(typeof (cert.organizationName), "string", "Bad organizationName value");
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
});

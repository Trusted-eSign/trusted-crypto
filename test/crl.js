"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("CRL", function() {
    var crl;

    it("init", function() {
        crl = new trusted.pki.Crl();
        assert.equal(crl !== null, true);
    });

    it("load", function() {
        crl.load(DEFAULT_RESOURCES_PATH + "/test.crl");
    });

    it("params", function() {
        assert.equal(typeof (crl.encoded), "object", "Bad encoded value");
        assert.equal(typeof (crl.signature), "object", "Bad signature value");
        assert.equal(typeof (crl.version), "number", "Bad version value");
        assert.equal(typeof (crl.thumbprint), "string", "Bad thumbprint value");
        assert.equal(typeof (crl.signatureAlgorithm), "string", "Bad signatureAlgorithme value");
        assert.equal(typeof (crl.signatureDigestAlgorithm), "string", "Bad signatureDigestAlgorithm value");
        assert.equal(typeof (crl.issuerName), "string", "Bad issuerName value");
        assert.equal(typeof (crl.issuerFriendlyName), "string", "Bad issuerFriendlyName value");
        assert.equal(typeof (crl.lastUpdate), "object", "Bad lastUpdate value");
        assert.equal(typeof (crl.nextUpdate), "object", "Bad nextUpdate value");
        assert.equal(typeof (crl.authorityKeyid), "string", "Bad authorityKeyid value");
        assert.equal(typeof (crl.crlNumber), "string", "Bad crlNumber value");
    });

    it("export", function() {
        var buf;

        buf = crl.export();
        assert.equal(Buffer.isBuffer(buf), true);
    });

    it("duplicate", function() {
        var crl1, crl2;

        crl1 = trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl");
        crl2 = crl1.duplicate();
        assert.equal(crl1.thumbprint === crl2.thumbprint, true, "CRL are not equals");
    });

    it("equals", function() {
        var crl1, crl2;

        crl1 = trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl");
        crl2 = trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/sfsca.crl");
        assert.equal(crl1.equals(crl1), 0, "CRL are equals");
        assert.equal(crl1.equals(crl2), -1, "CRL are not equals");
    });

    it("hash", function() {
        var crl1 = trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl");

        var hash1 = crl1.hash();
        var hash2 = crl1.hash("sha1");
        var hash3 = crl1.hash("sha256");

        assert.equal(hash1.length, 40, "SHA1 length 40");
        assert.equal(hash2.length, 40, "SHA1 length 40");
        assert.equal(hash3.length, 64, "SHA256 length 64");

        assert.equal(hash1 === hash2, true, "Hashes are not equals");
    });

    it("revoked", function() {
        var crl1, rvst, rv;

        crl1 = trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl");
        rvst = crl1.revoked;

        assert.equal(rvst.length === 17, true, "Incorrect length");

        rv = rvst.items(0);
        assert.equal(rv.duplicate().serialNumber === "782533159C9BDAC24414B6D0C478E0C0E06C6FBF", true, "Error get serial number");
        assert.equal(rv.duplicate().revocationDate === "Apr  7 20:43:24 2011 GMT", true, "Error duplicate");
        assert.equal(rv.revocationDate === "Apr  7 20:43:24 2011 GMT", true, "Error revocation date");
        assert.equal(rv.reason === "Superseded", true, "Error revocation reason");

        rvst.removeAt(0);
        assert.equal(rvst.length === 16, true, "Error remove revoked");

        rvst.push(rv);
        assert.equal(rvst.length === 17 && rvst.items(16).revocationDate === "Apr  7 20:43:24 2011 GMT", true, "Error push revoked");
    });
});

"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("CertificateCollection", function() {
    it("push", function() {
        var certs = new trusted.pki.CertificateCollection();

        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt"));
        assert.equal(certs.length, 1);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt"));
        assert.equal(certs.length, 2);
    });

    it("remove", function() {
        var certs = new trusted.pki.CertificateCollection();

        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt"));
        assert.equal(certs.length, 1);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt"));
        assert.equal(certs.length, 2);
        certs.pop();
        assert.equal(certs.length, 1);
        certs.removeAt(0);
        assert.equal(certs.length, 0);
    });

    it("items", function() {
        var certs = new trusted.pki.CertificateCollection();
        var cert;

        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt"));
        assert.equal(certs.length, 1);
        cert = certs.items(0);
        assert.equal(cert.version, 2);
    });
});

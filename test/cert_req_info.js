"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("CertificationRequestInfo", function() {
    var certReqInfo;
    var key;

    it("init", function() {
        certReqInfo = new trusted.pki.CertificationRequestInfo();
        assert.equal(certReqInfo !== null, true);

        key = trusted.pki.Key.readPublicKey(DEFAULT_RESOURCES_PATH + "/pubkey.key", trusted.DataFormat.PEM, "");
        assert.equal(key !== null, true);
    });

    it("create", function() {
        certReqInfo.subject = "/C=US/O=Test/CN=example.com";
        assert.equal(typeof (certReqInfo.subject), "string", "Bad subject value");

        certReqInfo.version = 2;
        assert.equal(typeof (certReqInfo.version), "number", "Bad version value");

        certReqInfo.publicKey = key;
        assert.equal(typeof (certReqInfo.publicKey), "object", "Bad public key value");
    });
});

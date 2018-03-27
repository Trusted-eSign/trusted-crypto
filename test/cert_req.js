"use strict";

var assert = require("assert");
var trusted = require("../index.js");
var fs = require("fs");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";
var SUBJECT_NAME = "/C=US/O=Test/CN=example.com";

describe("CertificationRequest", function() {
    var certReq;
    var certReqFromInfo;
    var certReqInfo;
    var publickey;
    var privatekey;

    it("init", function() {
        certReq = new trusted.pki.CertificationRequest();
        assert.equal(certReq !== null, true);

        certReqInfo = new trusted.pki.CertificationRequestInfo();
        assert.equal(certReqInfo !== null, true);

        publickey = trusted.pki.Key.readPublicKey(DEFAULT_RESOURCES_PATH + "/pubkey.key", trusted.DataFormat.PEM, "");
        assert.equal(publickey !== null, true);

        privatekey = trusted.pki.Key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");
        assert.equal(privatekey !== null, true);
    });

    it("create", function() {
        certReq.subject = SUBJECT_NAME;
        assert.equal(typeof (certReq.subject), "string", "Bad subject value");

        certReqInfo.version = 2;
        assert.equal(typeof (certReq.version), "number", "Bad version value");

        certReq.publicKey = publickey;
        assert.equal(typeof (certReq.publicKey), "object", "Bad public key value");
    });

    it("create from CertificationRequestInfo", function() {
        certReqInfo.subject = SUBJECT_NAME;
        assert.equal(typeof (certReqInfo.subject), "string", "Bad subject value");

        certReqInfo.version = 2;
        assert.equal(typeof (certReqInfo.version), "number", "Bad version value");

        certReqInfo.publicKey = publickey;
        assert.equal(typeof (certReqInfo.publicKey), "object", "Bad public key value");

        certReqFromInfo = new trusted.pki.CertificationRequest(certReqInfo.handle);
        assert.equal(certReqFromInfo.subject === certReq.subject, true);
    });

    it("sign/verify", function() {
        certReq.sign(privatekey, "SHA1");
        assert.equal(certReq.verify() === true, true, "Bad verify value");
    });

    it("save/load", function() {
        certReq.save(DEFAULT_OUT_PATH + "/testreq.pem", trusted.DataFormat.PEM);
        assert.equal(fs.statSync(DEFAULT_OUT_PATH + "/testreq.pem").size > 0, true, "Empty saved certificate request file");

        var req = new trusted.pki.CertificationRequest();

        assert.equal(certReq !== null, true);
        req.load(DEFAULT_OUT_PATH + "/testreq.pem", trusted.DataFormat.PEM);
        assert.equal(typeof (certReq.subject), "string", "Bad subject value");
    });
});

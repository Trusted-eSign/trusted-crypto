"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("SignedData", function() {
    var cert, key;

    before(function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM);
        key = trusted.pki.Key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");
    });

    it("Sign new data", function() {
        var sd;
        var signer;
        var policies;

        sd = new trusted.cms.SignedData();
        assert.equal(sd.content, null, "Init: content != null");
        assert.equal(sd.signers().length, 0, "Init: signers != 0");
        assert.equal(sd.certificates().length, 0, "Init: certificates != 0");

        sd.policies = ["noattributes", "noSignerCertificateVerify", "wrongPolicy"];

        signer = sd.createSigner(cert, key, "sha1");
        assert.equal(signer.digestAlgorithm.name, "sha1");
        assert.equal(sd.signers().length, 1);

        sd.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Hello world"
        };

        policies = sd.policies;

        assert.equal(policies.indexOf("noAttributes") !== -1, true);
        assert.equal(policies.indexOf("wrongPolicy") === -1, true);

        sd.sign();

        sd.save(DEFAULT_OUT_PATH + "/testsig.sig", trusted.DataFormat.PEM);

        assert.equal(sd.export() !== null, true);
        assert.equal(sd.verify() !== null, true);
    });

    it("load", function() {
        var cms;
        var signers;
        var signer;

        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_OUT_PATH + "/testsig.sig", trusted.DataFormat.PEM);

        assert.equal(cms.signers().length, 1, "Wrong signers length");
        assert.equal(cms.certificates().length, 1, "Wrong certificates length");
        assert.equal(cms.isDetached(), false, "Detached");

        signers = cms.signers();
        for (var i = 0; i < signers.length; i++) {
            signer = cms.signers(i);
            assert.equal(signer.digestAlgorithm.name, "sha1", "Wrong digest algorithm");
        }
    });
});

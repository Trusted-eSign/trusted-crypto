"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("SignedData", function() {
    var cert, key;
    var cms;

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

        sd.policies = ["noAttributes", "noSignerCertificateVerify", "wrongPolicy"];

        signer = sd.createSigner(cert, key);
        assert.equal(signer.digestAlgorithm.name, "sha256");
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

        assert.equal(sd.export() !== null, true, "sd.export()");
        assert.equal(sd.verify() !== false, true, "Verify signature");
    });

    it("load", function() {
        var signers;
        var signer;
        var signerId;

        cms = new trusted.cms.SignedData();
        cms.load(DEFAULT_OUT_PATH + "/testsig.sig", trusted.DataFormat.PEM);

        assert.equal(cms.signers().length, 1, "Wrong signers length");
        assert.equal(cms.certificates().length, 1, "Wrong certificates length");
        assert.equal(cms.isDetached(), false, "Detached");

        signers = cms.signers();
        for (var i = 0; i < signers.length; i++) {
            signer = cms.signers(i);
            assert.equal(signer.digestAlgorithm.name, "sha256", "Wrong digest algorithm");

            signer.certificate = cert;
            assert.equal(signer.verifyContent(cms.content) === true, true, "Verify signer content");
        }

        signerId = signer.signerId;
        assert.equal(typeof signerId.issuerName, "string", "Wrong issuer name");
        assert.equal(typeof signerId.serialNumber, "string", "Wrong serial number");
    });

    it("export PEM", function() {
        var buf = cms.export(trusted.DataFormat.PEM);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString().indexOf("-----BEGIN CMS-----") === -1, false);
    });

    it("export Default", function() {
        var buf = cms.export();

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
    });

    it("export DER", function() {
        var buf = cms.export(trusted.DataFormat.DER);

        assert.equal(Buffer.isBuffer(buf), true);
        assert.equal(buf.length > 0, true);
        assert.equal(buf.toString("hex").indexOf("06092a864886f70d010702") === -1, false);
    });

    it("import", function() {
        var tmpCms;

        var buf = cms.export(trusted.DataFormat.PEM);

        tmpCms = new trusted.cms.SignedData();
        tmpCms.import(buf, trusted.DataFormat.PEM);
        assert.equal(tmpCms.signers().length, 1, "Wrong signers length");
        assert.equal(tmpCms.certificates().length, 1, "Wrong certificates length");
        assert.equal(tmpCms.isDetached(), false, "Detached");
    });
});

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
    var ext1;
    var ext2;
    var exts;
    var oid;


    before(function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }
    });


    it("init", function() {
        certReq = new trusted.pki.CertificationRequest();
        assert.equal(certReq !== null, true);

        certReqInfo = new trusted.pki.CertificationRequestInfo();
        assert.equal(certReqInfo !== null, true);

        publickey = trusted.pki.Key.readPublicKey(DEFAULT_RESOURCES_PATH + "/pubkey.key", trusted.DataFormat.PEM, "");
        assert.equal(publickey !== null, true);

        privatekey = trusted.pki.Key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");
        assert.equal(privatekey !== null, true);

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

    it("create", function() {
        var atrs = [
            { type: "C", value: "RU" },
            { type: "CN", value: "example.com" },
            { type: "O", value: "Test" },
            { type: "1.2.643.100.3", value: "12295279771" }
        ];

        certReq.subject = atrs;
        assert.equal(typeof (certReq.subject), "string", "Bad subject value");

        certReq.version = 2;
        assert.equal(typeof (certReq.version), "number", "Bad version value");

        certReq.publicKey = publickey;
        assert.equal(typeof (certReq.publicKey), "object", "Bad public key value");

        certReq.extensions = exts;
        assert.equal(typeof (certReq.extensions), "object", "Bad extensions value");
    });

    it("create from CertificationRequestInfo", function() {
        certReqInfo.subject = SUBJECT_NAME;
        assert.equal(typeof (certReqInfo.subject), "string", "Bad subject value");

        certReqInfo.version = 2;
        assert.equal(typeof (certReqInfo.version), "number", "Bad version value");

        certReqInfo.publicKey = publickey;
        assert.equal(typeof (certReqInfo.publicKey), "object", "Bad public key value");

        certReqFromInfo = new trusted.pki.CertificationRequest(certReqInfo.handle);
        assert.equal(typeof (certReqFromInfo.subject), "string", "Bad subject value");
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

    it("to certificate", function() {
        var cert;

        cert = certReq.toCertificate(365, privatekey);
        assert.equal(certReq !== null, true);
        assert.equal(typeof (cert.isSelfSigned), "boolean", "Error check self signed");
    });
});

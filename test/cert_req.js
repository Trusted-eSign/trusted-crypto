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
    var ext;
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

        exts = new trusted.pki.ExtensionCollection();
        assert.equal(exts !== null, true);


        oid = new trusted.pki.Oid("keyUsage");
        assert.equal(oid !== null, true);
        ext = new trusted.pki.Extension(oid, "critical,keyAgreement,dataEncipherment,nonRepudiation,digitalSignature");
        assert.equal(ext !== null, true);
        assert.equal(exts.length, 0);
        exts.push(ext);
        assert.equal(exts.length, 1);


        oid = new trusted.pki.Oid("extendedKeyUsage");
        assert.equal(oid !== null, true);
        ext = new trusted.pki.Extension(oid, "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4");
        assert.equal(ext !== null, true);
        exts.push(ext);
        assert.equal(exts.length, 2);

        // Custom extension (SubjectSignTool) with format utf8
        oid = new trusted.pki.Oid("1.2.643.100.111");
        assert.equal(oid !== null, true);
        ext = new trusted.pki.Extension(oid, "ASN1:FORMAT:UTF8,UTF8String:КриптоПро CSP версия 4.0");
        assert.equal(ext !== null, true);
        exts.push(ext);
        assert.equal(exts.length, 3);

        // Custom extension (IssuerSignTool) with format utf8
        oid = new trusted.pki.Oid("1.2.643.100.112");
        assert.equal(oid !== null, true);
        ext = new trusted.pki.Extension(oid, "ASN1:FORMAT:UTF8,UTF8String:КриптоПро CSP версия 3.6");
        assert.equal(ext !== null, true);
        exts.push(ext);
        assert.equal(exts.length, 4);

        oid = new trusted.pki.Oid("certificatePolicies");
        assert.equal(oid !== null, true);
        ext = new trusted.pki.Extension(oid, "1.2.643.100.113.1");
        assert.equal(ext !== null, true);
        exts.push(ext);
        assert.equal(exts.length, 5);
    });

    it("create", function() {
        var atrs = [
            { type: "C", value: "RU" },
            { type: "CN", value: "Иван Иванов" },
            { type: "localityName", value: "Yoshkar-Ola" },
            { type: "stateOrProvinceName", value: "Mari El" },
            { type: "O", value: "Test Org" },
            { type: "1.2.643.100.3", value: "12295279882" },
            { type: "1.2.643.3.131.1.1", value: "002465363366" }
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
        certReq.sign(privatekey);
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

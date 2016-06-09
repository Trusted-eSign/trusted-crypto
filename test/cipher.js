"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("CipherSYMMETRIC", function() {
    var cipher;

    it("init", function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        cipher = new trusted.pki.Cipher("aes256");
        assert.equal(cipher !== null, true);

    });

    it("method", function() {
        cipher.cryptoMethod = trusted.CryptoMethod.SYMMETRIC;
    });

    it("encrypt", function() {
        cipher.digest = "MD5";
        cipher.password = "4321";
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encSym.txt");
    });

    it("decrypt", function() {
        cipher.decrypt(DEFAULT_OUT_PATH + "/encSym.txt", DEFAULT_OUT_PATH + "/decSym.txt");
    });
});

describe("CipherASSYMETRIC", function() {
    var cipher;

    it("init", function() {
        cipher = new trusted.pki.Cipher("aes256");
        assert.equal(cipher !== null, true);
    });

    it("recipients", function() {
        var certs = new trusted.pki.CertificateCollection();

        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM));
        assert.equal(certs.length, 1);
        certs.push(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt", trusted.DataFormat.DER));
        assert.equal(certs.length, 2);

        cipher.recipientsCerts = certs;
    });

    it("encrypt", function() {
        cipher.encrypt(DEFAULT_RESOURCES_PATH + "/test.txt", DEFAULT_OUT_PATH + "/encAssym.txt", trusted.DataFormat.PEM);
    });

    it("recipient cert", function() {
        var cert = new trusted.pki.Certificate();

        assert.equal(cert !== null, true);
        cert.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM);

        cipher.recipientCert = cert;
    });

    it("recipient private key", function() {
        var key = new trusted.pki.Key();

        assert.equal(key !== null, true);
        key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");
        cipher.privKey = key;
    });

    it("decrypt", function() {
        cipher.decrypt(DEFAULT_OUT_PATH + "/encAssym.txt", DEFAULT_OUT_PATH + "/decAssym.txt", trusted.DataFormat.PEM);
    });
});

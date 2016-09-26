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

        cipher = new trusted.pki.Cipher();
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
        cipher = new trusted.pki.Cipher();
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

    it("recipient info", function() {
        var ris, ri;

        ris = cipher.getRecipientInfos(DEFAULT_OUT_PATH + "/encAssym.txt", trusted.DataFormat.PEM);
        assert.equal(ris.length, 2, "Recipients length 2");

        ri = ris.items(0);
        assert.equal(ri.issuerName, "/C=RU/ST=Mari El/L=Yola/O=Trusted/CN=Trusted/emailAddress=trusted@digt.ru", "Error issuer name");
        assert.equal(ri.serialNumber, "E8CF63BF8C889177", "Error serial number");
        assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM)) === 0, true, "Compare recipient cert");
        assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt", trusted.DataFormat.DER)) !== 0, true, "Compare recipient cert");

        ri = ris.items(1);
        assert.equal(ri.issuerName, "/C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Certification Authority", "Error issuer name");
        assert.equal(ri.serialNumber, "1B8612677AE19D", "Error serial number");
        assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM)) !== 0, true, "Compare recipient cert");
        assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt", trusted.DataFormat.DER)) === 0, true, "Compare recipient cert");
    });

    it("decrypt", function() {
        cipher.decrypt(DEFAULT_OUT_PATH + "/encAssym.txt", DEFAULT_OUT_PATH + "/decAssym.txt", trusted.DataFormat.PEM);
    });
});

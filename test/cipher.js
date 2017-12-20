"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_CERTSTORE_PATH = "test/CertStore";
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
        var inp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/test.txt"
        };
        var outp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_OUT_PATH + "/encSym.txt"
        };
        cipher.encrypt(inp, outp);
    });

    it("decrypt", function() {
        var inp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_OUT_PATH + "/encSym.txt"
        };
        var outp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_OUT_PATH + "/decSym.txt"
        };
        cipher.decrypt(inp, outp);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decSym.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });

    var encStr;
    var inputStr = "Text Текст 1234 !@#$%^&*()_+?";
    it("encrypt string", function() {
        encStr = "";
        cipher.digest = "MD5";
        cipher.password = "4321";
        var inp = {
            type: trusted.pki.CipherContentType.buffer,
            data: inputStr
        };
        var outp = {
            type: trusted.pki.CipherContentType.buffer,
            data: ""
        };
        encStr = cipher.encrypt(inp, outp);
    });

    it("decrypt string", function() {
        var inp = {
            type: trusted.pki.CipherContentType.buffer,
            data: encStr
        };
        var outp = {
            type: trusted.pki.CipherContentType.buffer,
            data: ""
        };
        var decStr = cipher.decrypt(inp, outp);

        assert.equal(inputStr === decStr, true, "Resource and decrypt text diff");
    });
});

describe("CipherASSYMETRIC", function() {
    var cipher;
    var ris, ri;
    var store, cert, key;

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
        var inp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_RESOURCES_PATH + "/test.txt"
        };
        var outp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_OUT_PATH + "/encAssym.txt"
        };
        cipher.encrypt(inp, outp, trusted.DataFormat.PEM);
    });

    it("recipient cert", function() {
        cert = new trusted.pki.Certificate();

        assert.equal(cert !== null, true);
        cert.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM);

        cipher.recipientCert = cert;
    });

    it("recipient private key", function() {
        key = new trusted.pki.Key();

        assert.equal(key !== null, true);
        key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");
        cipher.privKey = key;
    });

    it("recipient info", function() {
        ris = cipher.getRecipientInfos(DEFAULT_OUT_PATH + "/encAssym.txt", trusted.DataFormat.PEM);
        assert.equal(ris.length, 2, "Recipients length 2");

        ri = ris.items(1);
        if (ri.serialNumber === "FD7CF8FC52A1D181") {
            assert.equal(ri.issuerName, "/2.5.4.6=RU/2.5.4.8=Mari El/2.5.4.7=Yoshkar-Ola/2.5.4.10=Cifrovie Tehnologii/2.5.4.3=Test certificate/1.2.840.113549.1.9.1= trusted@digt.ru", "Error issuer name");
            assert.equal(ri.serialNumber, "FD7CF8FC52A1D181", "Error serial number");
            assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM)) === 0, true, "Compare recipient cert");
            assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt", trusted.DataFormat.DER)) !== 0, true, "Compare recipient cert");
        } else {
            assert.equal(ri.issuerName, "/2.5.4.6=IL/2.5.4.10=StartCom Ltd./2.5.4.11=Secure Digital Certificate Signing/2.5.4.3=StartCom Certification Authority", "Error issuer name");
            assert.equal(ri.serialNumber, "1B8612677AE19D", "Error serial number");
            assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM)) !== 0, true, "Compare recipient cert");
            assert.equal(ri.ktriCertCmp(trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt", trusted.DataFormat.DER)) === 0, true, "Compare recipient cert");
        }

        ri = ris.items(0);
        assert.equal(typeof (ri.issuerName), "string", "Error issuer name");
        assert.equal(typeof (ri.serialNumber), "string", "Error serial number");
    });

    it("find recipient in store", function() {
        var providerSystem;
        var item;
        var certWithKey;

        for (var j = 0; j < ris.length; j++) {
            ri = ris.items(j);
            if (ri.issuerName === "/2.5.4.6=IL/2.5.4.10=StartCom Ltd./2.5.4.11=Secure Digital Certificate Signing/2.5.4.3=StartCom Certification Authority", "Error issuer name") {
                break;
            }
        }

        store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
        assert.equal(store !== null, true);

        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM);
        key = trusted.pki.Key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");

        store.addCert(providerSystem.handle, "MY", cert, 0);
        store.addKey(providerSystem.handle, key, "");

        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem !== null, true);
        store.addProvider(providerSystem.handle);

        var certs = store.find({
            issuerName: ri.issuerName,
            serial: ri.serialNumber
        });

        for (var i = 0; i < certs.length; i++) {
            item = certs[i];
            if (item.key) {
                certWithKey = store.getItem(item);
            }
            assert.equal(item.type, "CERTIFICATE");
            if (item.type === "CERTIFICATE") {
                cert = store.getItem(item);
                assert.equal(cert.subjectName.length > 0, true);
            }
        }

        assert.equal(!!certWithKey, true, "Error get certificate with key");

        key = store.findKey({
            type: ["CERTIFICATE"],
            provider: ["SYSTEM"],
            category: ["MY"],
            hash: certWithKey.thumbprint.toString("hex")
        });

        assert.equal(!!key, true, "Error get private key");
    });

    it("decrypt", function() {
        cipher = new trusted.pki.Cipher();
        cipher.recipientCert = cert;
        cipher.privKey = store.getItem(key);

        var inp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_OUT_PATH + "/encAssym.txt"
        };
        var outp = {
            type: trusted.pki.CipherContentType.url,
            data: DEFAULT_OUT_PATH + "/decAssym.txt"
        };

        cipher.decrypt(inp, outp, trusted.DataFormat.PEM);

        var res = fs.readFileSync(DEFAULT_RESOURCES_PATH + "/test.txt");
        var out = fs.readFileSync(DEFAULT_OUT_PATH + "/decAssym.txt");

        assert.equal(res.toString() === out.toString(), true, "Resource and decrypt file diff");
    });
});

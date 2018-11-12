"use strict";

var assert = require("assert");
var os = require("os");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_CERTSTORE_PATH = "test/CertStore";
var DEFAULT_RESOURCES_PATH = "test/resources";
var CPROCSP = 0;

/**
* Check file exists
* @param  {string} filePath Path to file
* @returns {boolean} file exists?
*/
function checkFile(filePath) {
    try {
        return fs.statSync(filePath).isFile();
    } catch (err) {
        return false;
    }
}

before(function() {
    if (checkFile(DEFAULT_CERTSTORE_PATH + "/cash.json")) {
        fs.unlinkSync(DEFAULT_CERTSTORE_PATH + "/cash.json");
    }
});

describe("Store", function() {
    var store;
    var providerSystem, providerMicrosoft, providerCryptopro;
    var certWithKey;
    var uri;
    var osType = os.type();

    it("init", function() {
        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem !== null, true);

        store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
        assert.equal(store !== null, true);
    });

    it("add pki objects", function() {
        var cert, newCert;
        var crl, newCrl;
        var key, newKey;
        var csr;

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM);
        crl = trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl");
        key = trusted.pki.Key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");
        csr = trusted.pki.CertificationRequest.load(DEFAULT_RESOURCES_PATH + "/test.csr", trusted.DataFormat.PEM, "");

        uri = store.addCert(providerSystem.handle, "MY", cert);
        store.addCrl(providerSystem.handle, "CRL", crl);
        store.addKey(providerSystem.handle, key, "");
        store.addCsr(providerSystem.handle, "MY", csr);

        newCert = trusted.pki.Certificate.load(DEFAULT_CERTSTORE_PATH + "/MY/9411a862691c1846b24da3c89299799856876404_779e37cd0423417592ccc9c20ce3d83c665050c5.crt", trusted.DataFormat.PEM);
        assert.equal(cert.thumbprint === newCert.thumbprint, true);

        newCrl = trusted.pki.Crl.load(DEFAULT_CERTSTORE_PATH + "/CRL/1ebb0526075855661c09d7d9b59abd950bdae0ef.crl");
        assert.equal(crl.thumbprint === newCrl.thumbprint, true);

        newKey = trusted.pki.Key.readPrivateKey(DEFAULT_CERTSTORE_PATH + "/MY/779e37cd0423417592ccc9c20ce3d83c665050c5.key", trusted.DataFormat.PEM, "");
        assert.equal(newKey !== null, true);
    });

    it("add providers", function() {
        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem !== null, true);
        store.addProvider(providerSystem.handle);

        if (osType === "Windows_NT") {
            providerMicrosoft = new trusted.pkistore.ProviderMicrosoft();
            assert.equal(providerMicrosoft !== null, true);
            store.addProvider(providerMicrosoft.handle);
        } else if (CPROCSP) {
            providerCryptopro = new trusted.pkistore.ProviderCryptopro();
            assert.equal(providerCryptopro !== null, true);
            store.addProvider(providerCryptopro.handle);
        }
    });

    it("find", function() {
        var item;
        var cert;

        var certs = store.find({
            type: ["CERTIFICATE"],
            category: ["MY"]
        });

        for (var i = 0; i < certs.length; i++) {
            item = certs[i];
            if (item.key) {
                certWithKey = store.getItem(item);
                break;
            }
        }

        for (i = 0; i < certs.length; i++) {
            item = certs[i];
            assert.equal(item.type, "CERTIFICATE");

            if (item.provider === "MICROSOFT") {
                cert = store.getItem(item);
                assert.equal(cert.subjectName.length > 0, true);
                assert.equal(typeof (providerMicrosoft.hasPrivateKey(cert)), "boolean", "Bad hasPrivateKey value type");
                break;
            }
        }

        assert.equal(!!certWithKey, true, "Error get certificate with key");

        var key = store.findKey({
            type: ["CERTIFICATE"],
            provider: ["SYSTEM"],
            category: ["MY"],
            hash: certWithKey.thumbprint.toString("hex")
        });

        assert.equal(!!key, true, "Error get private key");
    });

    it("json", function() {
        var items;
        var exportPKI;

        items = store.find();

        if (store.cash) {
            store.cash.import(items);
            exportPKI = store.cash.export();
        }

        assert.equal(exportPKI.length > 0, true);
    });

    it("Object to PkiItem", function() {
        var item;

        item = providerSystem.objectToPkiItem(uri);
        assert.equal(item !== null, true);
    });

});

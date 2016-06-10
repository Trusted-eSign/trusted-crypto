"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_CERTSTORE_PATH = "test/CertStore";
var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("Chain", function() {
    var store;
    var providerSystem;
    var chain;
    var outChain;
    var rv;

    it("init", function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        chain = new trusted.pki.Chain();
        assert.equal(chain !== null, true);

        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem !== null, true);

        store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
        assert.equal(store !== null, true);

        rv = new trusted.pki.Revocation();
        assert.equal(rv !== null, true);

        store.addProvider(providerSystem.handle);
    });

    it("build", function() {
        var certs;
        var cert1, cert2, cert3, cert4;

        certs = new trusted.pki.CertificateCollection();
        assert.equal(certs !== null, true);

        cert1 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test-ru.crt", trusted.DataFormat.DER);
        assert.equal(cert1 !== null, true);
        certs.push(cert1);

        cert2 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM);
        assert.equal(cert2 !== null, true);
        certs.push(cert2);

        cert3 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test.crt", trusted.DataFormat.DER);
        assert.equal(cert3 !== null, true);
        certs.push(cert3);

        cert4 = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/test2.crt", trusted.DataFormat.PEM);
        assert.equal(cert4 !== null, true);
        certs.push(cert4);

        assert.equal(certs.length === 4, true);

        outChain = chain.buildChain(cert3, certs);

        assert.equal(outChain.length === 2, true);
    });

    it("verify", function() {
        var crl;
        var crls;

        crl = trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/sfsca.crl");

        store.addCrl(providerSystem.handle, "CRL", crl, 0);
        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem !== null, true);
        store.addProvider(providerSystem.handle);

        crls = new trusted.pki.CrlCollection();

        for (var i = 0; i < outChain.length; i++) {
            var tmpCrl = rv.getCrlLocal(outChain.items(i), store);

            if (tmpCrl && rv.checkCrlTime(tmpCrl)) {
                crls.push(tmpCrl);
            }
        }

        assert.equal(chain.verifyChain(outChain, crls) === true, true);
    }).timeout(5000);

    it("download CRL", function(done) {
        var testCert;
        var crl;
        var pathForSave;
        var distPoints;

        testCert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/github.crt", trusted.DataFormat.PEM);
        assert.equal(testCert !== null, true);

        pathForSave = DEFAULT_OUT_PATH + "/temp.crl";
        distPoints = rv.getCrlDistPoints(testCert);
        assert.equal(distPoints.length === 2, true);

        rv.downloadCRL(distPoints, pathForSave, function(err, res) {
            if (err) {
                done(err);
            } else {
                crl = res;
                store.addCrl(providerSystem.handle, "CRL", crl, 0);

                done();
            }
        });
    }).timeout(10000);
});

"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("PKCS12", function() {
    var p12;

    it("init", function() {
        p12 = new trusted.pki.Pkcs12();
        assert.equal(p12 !== null, true);
    });

    it("load", function() {
        p12.load(DEFAULT_RESOURCES_PATH + "/p12.pfx");
    });

    it("parse", function() {
        var cert;
        var key;
        var ca;

        cert = p12.certificate("");
        assert.equal(cert !== null, true);

        key = p12.key("");
        assert.equal(key !== null, true);

        ca = p12.ca("");
        assert.equal(ca.length, 1);
    });

    it("create", function() {
        var cert;
        var key;
        var p12Res;

        cert = trusted.pki.Certificate.load(DEFAULT_RESOURCES_PATH + "/cert1.crt", trusted.DataFormat.PEM);
        assert.equal(cert !== null, true);

        key = trusted.pki.Key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");
        assert.equal(key !== null, true);

        p12Res = p12.create(cert, key, null, "1", "test_name");
        assert.equal(p12Res !== null, true);
    });
});

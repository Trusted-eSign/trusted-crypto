"use strict";

var assert = require("assert");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";

describe("CrlCollection", function() {
    it("push", function() {
        var crls = new trusted.pki.CrlCollection();

        assert.equal(crls.length, 0);
        crls.push(trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl"));
        assert.equal(crls.length, 1);
        crls.push(trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/sfsca.crl"));
        assert.equal(crls.length, 2);
    });

    it("remove", function() {
        var crls = new trusted.pki.CrlCollection();

        assert.equal(crls.length, 0);
        crls.push(trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl"));
        assert.equal(crls.length, 1);
        crls.push(trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/sfsca.crl"));
        assert.equal(crls.length, 2);
        crls.pop();
        assert.equal(crls.length, 1);
        crls.removeAt(0);
        assert.equal(crls.length, 0);
    });

    it("items", function() {
        var crls = new trusted.pki.CrlCollection();
        var crl;

        assert.equal(crls.length, 0);
        crls.push(trusted.pki.Crl.load(DEFAULT_RESOURCES_PATH + "/test.crl"));
        assert.equal(crls.length, 1);
        crl = crls.items(0);
        assert.equal(typeof (crl.version), "number", "Bad version value");
    });
});

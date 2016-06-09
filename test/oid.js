"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("OID", function() {
    it("create", function() {
        var oid = new trusted.pki.Oid("2.5.4.3");

        assert.equal(oid.value, "2.5.4.3");
        assert.equal(oid.longName, "commonName");
        assert.equal(oid.shortName, "CN");
    });

    it("create with error", function() {
        assert.throws(function() {
            return new trusted.pki.Oid("2.5.4.3_error");
        });
    });
});

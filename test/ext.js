"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("Extension", function() {
    var ext;
    var oid;

    it("create", function() {
        oid = new trusted.pki.Oid("keyUsage");
        assert.equal(oid !== null, true);

        ext = new trusted.pki.Extension(oid, "critical,digitalSignature,keyEncipherment");
        assert.equal(ext !== null, true);
    });

    it("props", function() {
        assert.equal(ext.critical === true, true);

        ext.critical = false;
        assert.equal(ext.critical === false, true);

        var typeId = ext.typeId;

        assert.equal(typeId.value, "2.5.29.15", "Bad NID");
        assert.equal(typeId.longName, "X509v3 Key Usage");
        assert.equal(typeId.shortName, "keyUsage");
    });
});

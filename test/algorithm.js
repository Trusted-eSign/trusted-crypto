"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("Algorithm", function() {
    it("create", function() {
        var alg = new trusted.pki.Algorithm("SHA");

        assert.equal(alg.typeId.shortName, "SHA");
        assert.equal(alg.name, "sha");
        assert.equal(alg.duplicate().name, "sha");
        assert.equal(alg.isDigest(), true);
    });

    it("create with error", function() {
        assert.throws(function() {
            return new trusted.pki.Algorithm("SHA123_error");
        });
    });
});

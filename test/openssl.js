"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("OPENSSL", function() {
    it("stop", function() {
        trusted.common.OpenSSL.stop();

        assert.equal(trusted.common.OpenSSL.printErrors(), "");
    });

    it("run", function() {
        trusted.common.OpenSSL.run();

        trusted.pki.Certificate.load("undefined");
        assert.equal(trusted.common.OpenSSL.printErrors().length > 0, true);
    });
});

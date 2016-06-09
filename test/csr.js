"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_RESOURCES_PATH = "test/resources";
var DEFAULT_OUT_PATH = "test/out";

describe("CSR", function() {
    var key, csr;

    it("init", function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        key = trusted.pki.Key.readPrivateKey(DEFAULT_RESOURCES_PATH + "/cert1.key", trusted.DataFormat.PEM, "");

        csr = new trusted.pki.CSR("/C=US/O=Test/CN=example.com", key, "SHA1");
        assert.equal(csr !== null, true);
    });

    it("save", function() {
        csr.save(DEFAULT_OUT_PATH + "/test.csr");
    });

    it("encoded", function() {
        assert.equal(typeof (csr.encoded), "object", "Bad encoded value");
    });
});

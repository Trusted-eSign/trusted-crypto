"use strict";

var assert = require("assert");
var fs = require("fs");
var trusted = require("../index.js");

var DEFAULT_OUT_PATH = "test/out";

describe("Key", function() {
    var key, privateKey;
    var keyPair;

    it("init", function() {
        try {
            fs.statSync(DEFAULT_OUT_PATH).isDirectory();
        } catch (err) {
            fs.mkdirSync(DEFAULT_OUT_PATH);
        }

        key = new trusted.pki.Key();
        assert.equal(key !== null, true);
    });

    it("generate", function() {
        keyPair = key.generate(trusted.DataFormat.PEM, trusted.PublicExponent.RSA_F4, 1024);
    });

    it("save private", function() {
        keyPair.writePrivateKey(DEFAULT_OUT_PATH + "/privkey_s.key", trusted.DataFormat.PEM, "1234");
    });

    it("read private", function() {
        privateKey = key.readPrivateKey(DEFAULT_OUT_PATH + "/privkey_s.key", trusted.DataFormat.PEM, "1234");
        assert.equal(privateKey !== null, true);
    });

    it("save public", function() {
        key.writePublicKey(DEFAULT_OUT_PATH + "/pubkey_s.key", trusted.DataFormat.PEM);
    });

    it("read public", function() {
        key.readPublicKey(DEFAULT_OUT_PATH + "/pubkey_s.key", trusted.DataFormat.PEM);
        assert.equal(key !== null, true);
    });
});

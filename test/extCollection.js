"use strict";

var assert = require("assert");
var trusted = require("../index.js");

describe("ExtensionCollection", function() {
    var ext1;
    var ext2;
    var exts;
    var oid;

    it("init", function() {
        oid = new trusted.pki.Oid("keyUsage");
        assert.equal(oid !== null, true);

        ext1 = new trusted.pki.Extension(oid, "critical,digitalSignature,keyEncipherment");
        assert.equal(ext1 !== null, true);

        oid = new trusted.pki.Oid("subjectAltName");
        assert.equal(oid !== null, true);

        ext2 = new trusted.pki.Extension(oid, "email:test@example.com");
        assert.equal(ext2 !== null, true);
    });

    it("push", function() {
        exts = new trusted.pki.ExtensionCollection();
        assert.equal(exts !== null, true);

        assert.equal(exts.length, 0);
        exts.push(ext1);
        assert.equal(exts.length, 1);
        exts.push(ext2);
        assert.equal(exts.length, 2);
    });

    it("remove", function() {
        exts = new trusted.pki.ExtensionCollection();
        assert.equal(exts !== null, true);

        assert.equal(exts.length, 0);
        exts.push(ext1);
        assert.equal(exts.length, 1);
        exts.push(ext2);
        assert.equal(exts.length, 2);
        exts.pop();
        assert.equal(exts.length, 1);
        exts.removeAt(0);
        assert.equal(exts.length, 0);
    });

    it("items", function() {
        var ext;

        exts = new trusted.pki.ExtensionCollection();
        assert.equal(exts !== null, true);

        assert.equal(exts.length, 0);
        exts.push(ext1);
        assert.equal(exts.length, 1);

        ext = exts.items(0);
        assert.equal(typeof (ext.critical), "boolean", "Bad critical value");
        assert.equal(typeof (ext.typeId.value), "string", "Bad value");
    });
});

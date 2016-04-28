var assert = require('assert');
var trusted = require("../index.js")

describe('Certificate', function () {
    var p12;

    it('init', function () {
        p12 = new trusted.pki.Pkcs12()
        assert.equal(p12 != null, true);
    })

    it('load', function () {
        p12.load("test/p12.pfx");
    });

    it('parse', function () {
		var cert = p12.certificate('');
        assert.equal(cert != null, true);
        
        var key = p12.key('');
        assert.equal(key != null, true);
        
        var ca = p12.ca('');
        assert.equal(ca.length, 1);
    })
});
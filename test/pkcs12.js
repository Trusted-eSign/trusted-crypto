var assert = require('assert');
var trusted = require("../index.js")

describe('PKCS12', function () {
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
    });
    
    it('create', function () {
		var cert = trusted.pki.Certificate.load("test/cert1.crt", trusted.DataFormat.PEM);
        assert.equal(cert != null, true);
        
        var key = trusted.pki.Key.privkeyLoad("test/cert1.key", trusted.DataFormat.PEM, "");
        assert.equal(key != null, true);
        
        var p12Res = p12.create(cert, key, null, "1", "test_name");
        assert.equal(p12Res != null, true);
    })
});
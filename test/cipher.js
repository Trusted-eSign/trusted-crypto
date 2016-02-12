var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";

describe('CipherSYMMETRIC', function () {
	var cipher;
	
	it('init', function () {	
		cipher = new trusted.pki.Cipher("aes256");
        assert.equal(cipher != null, true);
		
    })
    
    it('method', function () {	
        cipher.cryptoMethod = trusted.CryptoMethod.SYMMETRIC;	
    })
	
	it('encrypt', function () {	
        cipher.digest = "MD5";
        cipher.password = "4321";
		cipher.encrypt("test/test.txt", "test/encSym.txt");		
    })
    
    it('params', function () {	
        console.log("salt:", cipher.rsalt);
        console.log("iv:", cipher.riv);
        console.log("key:", cipher.rkey);
        console.log("cipher:", cipher.algorithm);
        console.log("cipher mode:", cipher.mode);
        console.log("digest:", cipher.dgst);		
    })
    
    it('decrypt', function () {	
		cipher.decrypt("test/encSym.txt", "test/decSym.txt");		
    })
	
})

describe('CipherASSYMETRIC', function () {
	var cipher;
	
	it('init', function () {	
		cipher = new trusted.pki.Cipher("aes256");
        assert.equal(cipher != null, true);
		
    })
    
    it('recipients', function () {
        var certs = new trusted.pki.CertificateCollection();       
        assert.equal(certs.length, 0);
        certs.push(trusted.pki.Certificate.load("test/cert1.crt", trusted.DataFormat.PEM));
        assert.equal(certs.length, 1);
        certs.push(trusted.pki.Certificate.load("test/test.crt", trusted.DataFormat.DER));
        assert.equal(certs.length, 2);	
        
		cipher.recipientsCerts = certs;		
    })
	
	it('encrypt', function () {	
		cipher.encrypt("test/test.txt", "test/encAssym.txt", trusted.DataFormat.PEM);		
    })
    
    it('params', function () {	
        console.log("cipher:", cipher.algorithm);
        console.log("cipher mode:", cipher.mode);	
    })
    
    it('recipient cert', function () {
        var cert = new trusted.pki.Certificate();       
        assert.equal(cert != null, true);
        cert.load("test/cert1.crt", trusted.DataFormat.PEM);
        
		cipher.recipientCert = cert;		
    })
    
    it('recipient private key', function () {
        var key = new trusted.pki.Key();       
        assert.equal(key != null, true);
        
        key.privkeyLoad("test/cert1.key", trusted.DataFormat.PEM, "");
        
		cipher.privKey = key;		
    })
    
    it('decrypt', function () {	
		cipher.decrypt("test/encAssym.txt", "test/decAssym.txt", trusted.DataFormat.PEM);		
    })
	
})
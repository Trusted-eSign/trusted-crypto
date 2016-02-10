var assert = require('assert');
var trusted = require("../index.js")

describe('Cipher', function () {
	var cipher;
	
	it('init', function () {	
		cipher = new trusted.pki.Cipher("des-ede3-cbc");
        assert.equal(cipher != null, true);
		
    })
	
	it('encrypt', function () {	
        cipher.digest = "MD5";
        cipher.password = "4321";
		cipher.encrypt("test/test.txt", "test/enc.txt");		
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
		cipher.decrypt("test/enc.txt", "test/dec.txt");		
    })
	
})
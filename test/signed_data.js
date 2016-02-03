var assert = require("assert");
var trusted = require("../index.js")

describe("SignedData", function () {
    var cert, key;
    
    before(function(){
        cert = trusted.pki.Certificate.load("test/cert1.crt", trusted.DataFormat.PEM);
        key = trusted.pki.Key.privkeyLoad("test/cert1.key", trusted.DataFormat.PEM, "");
    })
    
    it("Sign new data", function(){
        var sd = new trusted.cms.SignedData();
        assert.equal(sd.content, null, "Init: content != null");
        assert.equal(sd.signers().length, 0, "Init: signers != 0");
        assert.equal(sd.certificates().length, 0, "Init: certificates != 0");
        
        sd.policies = ["noattributes", "noSignerCertificateVerify", "wrongPolicy"];
        
        var signer = sd.createSigner(cert, key, "sha1");
        assert.equal(signer.digestAlgorithm.name, "sha1");
        // assert.equal(signer.signedAttributes().length, 1);
        assert.equal(sd.signers().length, 1);
        // assert.equal(sd.certificates().length, 1);
        
        sd.content = {
            type: trusted.cms.SignedDataContentType.buffer,
            data: "Hello world"
        }
        
        var policies = sd.policies;
        
        assert.equal(policies.indexOf("noAttributes") != -1, true);
        assert.equal(policies.indexOf("wrongPolicy") == -1, true);
        
        sd.sign();
		
		sd.save("test/testsig.sig", trusted.DataFormat.DER);
        
        assert.equal(sd.export() != null, true)        
        assert.equal(sd.verify() != null, true);        
    })
    
});

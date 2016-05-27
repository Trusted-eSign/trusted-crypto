var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";

describe('Chain', function () {
    var store;
    var providerSystem;
    var chain;
    var outChain;
    var rv;

    it('init', function () {
        chain = new trusted.pki.Chain();
        assert.equal(chain != null, true);

        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem != null, true);

        store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH + "/cash.json");
        assert.equal(store != null, true);
        
        rv = new trusted.pki.Revocation();
        assert.equal(rv != null, true);

        store.addProvider(providerSystem.handle);
    })

    it('build', function () {
        var certs = new trusted.pki.CertificateCollection();
        assert.equal(certs != null, true);

        var cert1 = trusted.pki.Certificate.load("test/test-ru.crt", trusted.DataFormat.DER);
        assert.equal(cert1 != null, true);
        certs.push(cert1);

        var cert2 = trusted.pki.Certificate.load("test/cert1.crt", trusted.DataFormat.PEM);
        assert.equal(cert2 != null, true);
        certs.push(cert2);

        var cert3 = trusted.pki.Certificate.load("test/test.crt", trusted.DataFormat.DER);
        assert.equal(cert3 != null, true);
        certs.push(cert3);

        var cert4 = trusted.pki.Certificate.load("test/test2.crt", trusted.DataFormat.PEM);
        assert.equal(cert4 != null, true);
        certs.push(cert4);

        assert.equal(certs.length == 4, true);

        outChain = chain.buildChain(cert3, certs);

        assert.equal(outChain.length == 2, true);
    });

    it('verify', function () {
        var crl = trusted.pki.Crl.load("test/sfsca.crl");
        store.addCrl(providerSystem.handle, "CRL", crl, 0);
        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem != null, true);
        store.addProvider(providerSystem.handle);

        var crls = new trusted.pki.CrlCollection();
        var rv = new trusted.pki.Revocation();
        for (var i = 0; i < outChain.length; i++) {
            var tmpCrl = rv.getCrlLocal(outChain.items(i), store);
            if (tmpCrl && rv.checkCrlTime(tmpCrl)) {
                crls.push(tmpCrl)
            }
        }

        assert.equal(chain.verifyChain(outChain, crls) === true, true);
    });
    
    it('download CRL',  function (done) { 
       this.timeout(10000);        
       var testCert = trusted.pki.Certificate.load("test/test-ru.crt", trusted.DataFormat.DER);
       assert.equal(testCert != null, true);
       
       var pathForSave = DEFAULT_CERTSTORE_PATH + "/temp.crl";
       var crl;
          
       var distPoints = rv.getCrlDistPoints(testCert);
       assert.equal(distPoints.length === 5, true);
       
       rv.downloadCRL(distPoints, pathForSave, function(err, res){
           if (err){
               console.log(err);
               done(err);
           }
           else{
                crl = res;
                console.log("All CRL downloaded");
                console.log("Isuer name:", crl.issuerFriendlyName);
                
                store.addCrl(providerSystem.handle, "CRL", crl, 0); 
                
                done();
           }          
        });                             
  });
});

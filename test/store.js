var assert = require('assert');
var trusted = require("../index.js")
var async = require("async");

var DEFAULT_CERTSTORE_PATH = "test/CertStore";

describe('Store', function () {
	var store;
	var providerSystem, providerMicrosoft;
    var certWithKey;
    
	it('init', function () {
        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem != null, true);
       	
		store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH+"/cash.json");
        assert.equal(store != null, true);	
    })
    
    it('add pki objects', function () {       	
       var cert  = trusted.pki.Certificate.load("test/cert1.crt", trusted.DataFormat.PEM);
       var crl = trusted.pki.Crl.load("test/test.crl");
       var key = trusted.pki.Key.privkeyLoad("test/cert1.key", trusted.DataFormat.PEM, "");
       var csr = trusted.pki.CertificationRequest.load("test/test.csr", trusted.DataFormat.PEM, "");
       
       store.addCert(providerSystem.handle, "MY", cert, 0);
       store.addCrl(providerSystem.handle, "CRL", crl, 0);
       store.addKey(providerSystem.handle, key, "");
       store.addCsr(providerSystem.handle, "MY", csr);
       
       var newCert = trusted.pki.Certificate.load("test/CertStore/MY/84cd1d796cfb42d00166737c6e16d596cf83695e_15b5c91c943cd687ccf6b85a7b28273f281d3eba.crt", trusted.DataFormat.PEM);
       assert.equal(cert.thumbprint == newCert.thumbprint, true);
       
       var newCrl = trusted.pki.Crl.load("test/CertStore/CRL/1ebb0526075855661c09d7d9b59abd950bdae0ef.crl");
       assert.equal(crl.thumbprint == newCrl.thumbprint, true);
       
       var newKey = trusted.pki.Key.privkeyLoad("test/CertStore/MY/15b5c91c943cd687ccf6b85a7b28273f281d3eba.key", trusted.DataFormat.PEM, "");
       assert.equal(newKey != null, true);
    })
    
    it('add providers', function () {	
        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem != null, true);
        store.addProvider(providerSystem.handle);
        
        providerMicrosoft = new trusted.pkistore.ProviderMicrosoft();
        assert.equal(providerMicrosoft != null, true);
        store.addProvider(providerMicrosoft.handle);	
    })
	
	it('find', function () {	
       var certs = store.find({
            type: ["CERTIFICATE"],
            category: ["MY"]        
        });
        
        for (var i = 0; i < certs.length; i++) {
            var item = certs[i];
            if (item.key) {
                certWithKey = store.getItem(item);
            }
            assert.equal(item.type, "CERTIFICATE");
            if (item.type === "CERTIFICATE") {
                var cert = store.getItem(item);
                assert.equal(cert.subjectName.length > 0, true);
            }
        }
        
    })
    
    it('findKey', function () {	
       var key = store.findKey({
            type: ["CERTIFICATE"],
            provider: ["SYSTEM"],
            category: ["MY"],
            hash: certWithKey.thumbprint.toString('hex')
        });
        
        assert.equal(!!key, true, "Отсутствует ключ для сертификата");     
    })
    
    it('json', function () {	
       var items = store.find();
       store.cash.import(items);
       var exportPKI = store.cash.export();
       assert.equal(exportPKI.length > 0, true);
    })
       
    it('download CRL',  function (done) { 
       this.timeout(10000);        
       var testCert = trusted.pki.Certificate.load("test/test-ru.crt", trusted.DataFormat.DER);
       var path = DEFAULT_CERTSTORE_PATH + "/temp.crl";
       var crl;
           

       store.downloadCRL(testCert, path, function(err, res){
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
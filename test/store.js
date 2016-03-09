var assert = require('assert');
var trusted = require("../index.js")

var DEFAULT_CERTSTORE_PATH = "test/CertStore";

describe('Store', function () {
	var store;
	var providerSystem;
    var certWithKey;
    
	it('init', function () {	
		store = new trusted.pkistore.PkiStore(DEFAULT_CERTSTORE_PATH+"/cash.json");
        assert.equal(store != null, true);	
    })
    
    it('add provider', function () {	
        providerSystem = new trusted.pkistore.Provider_System(DEFAULT_CERTSTORE_PATH);
        assert.equal(providerSystem != null, true);
        store.addProvider(providerSystem.handle);	
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
    	
})
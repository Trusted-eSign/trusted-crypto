var trusted = require("./index.js");
var cms = new trusted.Cms.SignedData();

cms.load("test/test02.txt.sig");

var cert = trusted.Pki.Certificate.load("test/test.crt");

var signers = cms.signers();
for (var i in signers) {
    var signer = signers[i];
    console.log(signer.digestAlgorithm.name);
    var sattrs = signer.signedAttributes();
    console.log("Signed attrs:", sattrs.length);
    signer.certificate = cms.certificates(0);
    console.log("Cert:", signer.certificate.subjectName);
    console.log("Signed attr 1:", sattrs.items(0).export().toString("hex"));
    signer.signedAttributes(0).typeId
    signer.signedAttributes().items(0).typeId
    console.log("Signed attr 1 ASN1 type:", signer.signedAttributes(0).asnType);
    console.log("Signed attr 1 ASN1 TypeId:", sattrs.items(0).typeId.longName);
    console.log("Signed attr 1 ASN1 TypeId:", sattrs.items(0).typeId.value);
    
    var uattrs = signer.unsignedAttributes();
    console.log("Unsigned attrs:", uattrs.length);
}

var certs = cms.certificates();
for (var i in certs) {
    var cert = certs[i];
    console.log(cert.subjectName);
    console.log(cms.certificates(+i));
}
console.log("isDetached:", cms.isDetached());
//! CSR generation

use der::asn1::{BitString, BitStringRef};
use der::{Any, AnyRef, Decode, Encode, Result};

use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, SubjectPublicKeyInfo};

use x509_cert::attr::{Attribute, Attributes};
use x509_cert::request::*;
use x509_cert::{ext::Extensions, name::Name};

use const_oid::db::rfc5912::ID_EXTENSION_REQ;

use crate::certs_pqc::generate_signature;
use crate::CompositeParts;

/// Generate a certificate request containing the given name, public key and extensions
pub fn generate_csr(
    spkibuf: &[u8],
    subject: &Name,
    extensions: Option<Extensions>,
    cp: &CompositeParts,
) -> Result<Vec<u8>> {
    let spki_ar = SubjectPublicKeyInfo::<AnyRef<'_>, BitStringRef<'_>>::from_der(spkibuf).unwrap();

    let mut attributes = Attributes::new();
    let mut er_attr = Attribute {
        oid: ID_EXTENSION_REQ,
        values: Default::default(),
    };
    let er_attr_val = extensions.to_vec().unwrap();
    let _r = er_attr
        .values
        .add(Any::from_der(er_attr_val.as_slice()).unwrap());
    let _r = attributes.add(er_attr);

    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: subject.clone(),
        public_key: spki_ar,
        attributes,
    };

    let tbs_cert = match info.to_vec() {
        Ok(tbs_cert) => tbs_cert,
        Err(e) => return Err(e),
    };

    let spki_alg1 = AlgorithmIdentifierOwned::from_der(&cp.spki_algs[0]).unwrap();
    let signing_alg_last_ar =
        AlgorithmIdentifier::<AnyRef<'_>>::from_der(cp.signing_algs.last().unwrap()).unwrap();

    let s = if cp.signing_keys.len() > 1 {
        let spki_alg2 = AlgorithmIdentifierOwned::from_der(&cp.spki_algs[1]).unwrap();
        let s1 = generate_signature(
            &spki_alg1.oid,
            cp.signing_keys[0].as_slice(),
            tbs_cert.as_slice(),
        );
        let s2 = generate_signature(
            &spki_alg2.oid,
            cp.signing_keys[1].as_slice(),
            tbs_cert.as_slice(),
        );

        let sig = vec![
            BitString::from_bytes(s1.as_slice()).unwrap(),
            BitString::from_bytes(s2.as_slice()).unwrap(),
        ];
        sig.to_vec().unwrap()
    } else {
        generate_signature(
            &spki_alg1.oid,
            cp.signing_keys[0].as_slice(),
            tbs_cert.as_slice(),
        )
    };
    let signature = BitString::from_bytes(s.as_slice()).unwrap();

    let c = CertReq {
        info,
        algorithm: signing_alg_last_ar,
        signature,
    };
    Ok(c.to_vec().unwrap())
}

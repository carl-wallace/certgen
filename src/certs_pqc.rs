//! Things related to certificate generation (PQC)

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
use rand_core::{OsRng, RngCore};

use subtle_encoding::hex;

#[cfg(feature = "pqc")]
use pqcrypto_dilithium::*;
#[cfg(feature = "pqc")]
use pqcrypto_falcon::{falcon1024, falcon512};
#[cfg(feature = "pqc")]
use pqcrypto_sphincsplus::*;
#[cfg(feature = "pqc")]
use pqcrypto_traits::sign::{PublicKey as OtherPublicKey, SecretKey};

use const_oid::db::rfc5280::*;
use der::asn1::{BitString, OctetString, OctetStringRef, UtcTime};
use der::{Any, Decode, Encode, Result};

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::PublicKey;

use sha1::{Digest, Sha1};

use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use certval::{
    encode_dn_from_string, PKIXALG_ECDSA_WITH_SHA224, PKIXALG_ECDSA_WITH_SHA256,
    PKIXALG_ECDSA_WITH_SHA384, PKIXALG_ECDSA_WITH_SHA512, PKIXALG_EC_PUBLIC_KEY, PKIXALG_SECP256R1,
};
use const_oid::ObjectIdentifier;
use der::pem::LineEnding;
use pqckeys::oak::OneAsymmetricKey;
use pqckeys::pqc_oids::*;
use pqcrypto_traits::sign::DetachedSignature;
use x509_cert::crl::{CertificateList, TbsCertList};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::serial_number::SerialNumber;
use x509_cert::{
    ext::{Extension, Extensions},
    name::Name,
    time::{Time, Validity},
    Certificate, TbsCertificate, Version,
};

use crate::csrs::generate_csr;
use crate::CertGenArgs;
use crate::CompanyAndProducts;

pub fn is_ecdsa(oid: &ObjectIdentifier) -> bool {
    *oid == PKIXALG_ECDSA_WITH_SHA256
        || *oid == PKIXALG_ECDSA_WITH_SHA384
        || *oid == PKIXALG_ECDSA_WITH_SHA224
        || *oid == PKIXALG_ECDSA_WITH_SHA512
        || *oid == PKIXALG_SECP256R1
        || *oid == PKIXALG_EC_PUBLIC_KEY
}

pub fn is_diluthium2(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM2 || *oid == OQ_DILITHIUM2
}

pub fn is_diluthium3(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM3 || *oid == OQ_DILITHIUM3
}

pub fn is_diluthium5(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM5 || *oid == OQ_DILITHIUM5
}
pub fn is_diluthium2aes(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM_AES2 || *oid == OQ_DILITHIUM_AES2
}

pub fn is_diluthium3aes(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_DILITHIUM3 || *oid == ENTU_DILITHIUM_AES3 || *oid == OQ_DILITHIUM_AES3
}

pub fn is_diluthium5aes(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_DILITHIUM5 || *oid == ENTU_DILITHIUM_AES5 || *oid == OQ_DILITHIUM_AES5
}

pub fn is_falcon512(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_FALCON_512 || *oid == OQ_FALCON_512
}

pub fn is_falcon1024(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_FALCON_1024 || *oid == OQ_FALCON_1024
}

pub fn is_sphincsp_sha256_128f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_128F_ROBUST
}

pub fn is_sphincsp_sha256_128f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_128F_SIMPLE
}

pub fn is_sphincsp_sha256_128s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_128S_ROBUST
}

pub fn is_sphincsp_sha256_128s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_128S_SIMPLE
}

pub fn is_sphincsp_sha256_192f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_192F_ROBUST
}

pub fn is_sphincsp_sha256_192f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_192F_SIMPLE
}

pub fn is_sphincsp_sha256_192s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_192S_ROBUST
}

pub fn is_sphincsp_sha256_192s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_192S_SIMPLE
}

pub fn is_sphincsp_sha256_256f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_256F_ROBUST
}

pub fn is_sphincsp_sha256_256f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_256F_SIMPLE
}

pub fn is_sphincsp_sha256_256s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_256S_ROBUST
}

pub fn is_sphincsp_sha256_256s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_256S_SIMPLE
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeParts {
    pub signing_keys: Vec<Vec<u8>>,
    pub spki_algs: Vec<Vec<u8>>,
    pub signing_algs: Vec<Vec<u8>>,

    // At present, spkis and skids only receive one value. Implemented as Vec on off chance a
    // different encoding scheme is desired.
    pub spkis: Vec<Vec<u8>>,
    pub skids: Vec<Vec<u8>>,
}

impl Default for CompositeParts {
    /// PkiEnvironment::default returns a new [`PkiEnvironment`] with empty callback vectors for each
    /// type of callback except `oid_lookups`, which features the [`oid_lookup`] function.
    fn default() -> Self {
        CompositeParts::new()
    }
}

impl CompositeParts {
    /// PkiEnvironment::new returns a new [`PkiEnvironment`] with empty callback vectors for each type of callback
    pub fn new() -> CompositeParts {
        CompositeParts {
            signing_keys: vec![],
            skids: vec![],
            spki_algs: vec![],
            signing_algs: vec![],
            spkis: vec![],
        }
    }
}

pub fn calc_skid(spkibuf: &[u8]) -> Vec<u8> {
    let spki_hash = Sha1::digest(spkibuf).to_vec();
    let skid = OctetStringRef::new(spki_hash.as_slice()).unwrap();
    skid.to_vec().unwrap()
}

pub fn generate_keypair(
    pk_alg1: ObjectIdentifier,
    sig_alg1: ObjectIdentifier,
    skids: &mut Vec<Vec<u8>>,
    signing_keys: &mut Vec<Vec<u8>>,
    spki_algs: &mut Vec<Vec<u8>>,
    signing_algs: &mut Vec<Vec<u8>>,
    spkis: &mut Vec<Vec<u8>>,
) {
    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: sig_alg1,
        parameters: None,
    };
    signing_algs.push(signature_algorithm.to_vec().unwrap());

    if is_ecdsa(&sig_alg1) {
        let x = pk_alg1.to_vec().unwrap();
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: PKIXALG_EC_PUBLIC_KEY,
            parameters: Some(Any::from_der(x.as_slice()).unwrap()),
        };
        spki_algs.push(spki_algorithm.to_vec().unwrap());

        if pk_alg1 == PKIXALG_SECP256R1 {
            let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
            let verify_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
            let pk = PublicKey::from_encoded_point(&verify_key.to_encoded_point(false));
            let spki = pk.unwrap().to_encoded_point(false);
            let spkibuf = spki.as_bytes();
            let enc_skid = calc_skid(spkibuf);
            skids.push(enc_skid);

            let privkey2 = signing_key.to_bytes();
            signing_keys.push(privkey2.to_vec());

            let spki = SubjectPublicKeyInfoOwned {
                algorithm: spki_algorithm,
                subject_public_key: BitString::from_bytes(spkibuf).unwrap(),
            };
            spkis.push(spki.to_vec().unwrap());
        }
    } else {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: pk_alg1,
            parameters: None,
        };
        spki_algs.push(spki_algorithm.to_vec().unwrap());

        #[cfg(feature = "pqc")]
        let (pk, sk) = if is_diluthium2(&pk_alg1) {
            let (pk, sk) = dilithium2::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium3(&pk_alg1) {
            let (pk, sk) = dilithium3::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium5(&pk_alg1) {
            let (pk, sk) = dilithium5::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium2aes(&pk_alg1) {
            let (pk, sk) = dilithium2aes::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium3aes(&pk_alg1) {
            let (pk, sk) = dilithium3aes::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium5aes(&pk_alg1) {
            let (pk, sk) = dilithium5aes::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_falcon512(&pk_alg1) {
            let (pk, sk) = falcon512::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_falcon1024(&pk_alg1) {
            let (pk, sk) = falcon1024::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128f_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256128frobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128f_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256128fsimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128s_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256128srobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128s_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256128ssimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192f_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256192frobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192f_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256192fsimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192s_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256192srobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192s_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256192ssimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256f_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256256frobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256f_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256256fsimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256s_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256256srobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256s_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256256ssimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else {
            panic!()
        };
        //let vspkibuf = OctetString::new(pk).unwrap().to_vec().unwrap();
        //let spkibuf = vspkibuf.as_slice();
        let spkibuf = pk.as_slice();
        let enc_skid = calc_skid(spkibuf);
        skids.push(enc_skid);
        signing_keys.push(sk);
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_algorithm,
            subject_public_key: BitString::from_bytes(spkibuf).unwrap(),
        };
        spkis.push(spki.to_vec().unwrap());
    }
}

/// This function aims to support traditional single-key SubjectPublicKeyInfoOwned (SPKI) objects or
/// composite SPKI objects. It does not consider hybrid certificates at present. SKID is calculated
/// as the SHA1 of the encoded SPKI (including composite). Composite keys are always 2 keys.
///
/// The algorithm for the first (and possibly only) key is indicated in the args.pk_alg1 field. If
/// composite is used, then args.composite must be set and args.pk_alg2 indicates the algorithm.
pub fn generate_keypairs(args: &CertGenArgs) -> CompositeParts {
    let mut cp = CompositeParts::default();

    let pk_alg1 = ObjectIdentifier::new(args.pk_alg1.as_str()).unwrap();
    let sig_alg1 = ObjectIdentifier::new(args.sig_alg1.as_str()).unwrap();

    generate_keypair(
        pk_alg1,
        sig_alg1,
        &mut cp.skids,
        &mut cp.signing_keys,
        &mut cp.spki_algs,
        &mut cp.signing_algs,
        &mut cp.spkis,
    );

    if args.composite_pk.is_some() && args.pk_alg2.is_some() && args.sig_alg2.is_some() {
        let c_alg = match &args.composite_pk {
            Some(pk) => ObjectIdentifier::new(pk).unwrap(),
            None => panic!(),
        };
        let s_alg = match &args.composite_sig {
            Some(pk) => ObjectIdentifier::new(pk).unwrap(),
            None => panic!(),
        };
        let pk_alg2 = match &args.pk_alg2 {
            Some(pk) => ObjectIdentifier::new(pk).unwrap(),
            None => panic!(),
        };
        let sig_alg2 = match &args.sig_alg2 {
            Some(pk) => ObjectIdentifier::new(pk).unwrap(),
            None => panic!(),
        };
        generate_keypair(
            pk_alg2,
            sig_alg2,
            &mut cp.skids,
            &mut cp.signing_keys,
            &mut cp.spki_algs,
            &mut cp.signing_algs,
            &mut cp.spkis,
        );

        if args.pk_alg3.is_some() && args.sig_alg3.is_some() {
            let pk_alg3 = match &args.pk_alg3 {
                Some(pk) => ObjectIdentifier::new(pk).unwrap(),
                None => panic!(),
            };
            let sig_alg3 = match &args.sig_alg3 {
                Some(pk) => ObjectIdentifier::new(pk).unwrap(),
                None => panic!(),
            };
            generate_keypair(
                pk_alg3,
                sig_alg3,
                &mut cp.skids,
                &mut cp.signing_keys,
                &mut cp.spki_algs,
                &mut cp.signing_algs,
                &mut cp.spkis,
            );
        }

        // add the composite items to ends of the lists
        let spki1 = SubjectPublicKeyInfoOwned::from_der(&cp.spkis[0]).unwrap();
        let spki2 = SubjectPublicKeyInfoOwned::from_der(&cp.spkis[1]).unwrap();
        let spki3 = if cp.spkis.len() > 2 {
            Some(SubjectPublicKeyInfoOwned::from_der(&cp.spkis[2]).unwrap())
        } else {
            None
        };

        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: c_alg,
            parameters: None,
        };

        let mut spki = vec![spki1, spki2];
        if let Some(s) = spki3 {
            spki.push(s);
        }

        let enc_spki = spki.to_vec().unwrap();
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_algorithm.clone(),
            subject_public_key: BitString::from_bytes(enc_spki.as_slice()).unwrap(),
        };
        let enc_cspki = spki.to_vec().unwrap();
        cp.spkis.push(enc_cspki);
        cp.spki_algs.push(spki_algorithm.to_vec().unwrap());

        let spki_alg1 = AlgorithmIdentifierOwned::from_der(&cp.signing_algs[0]).unwrap();
        let spki_alg2 = AlgorithmIdentifierOwned::from_der(&cp.signing_algs[1]).unwrap();
        let spki_alg3 = if cp.signing_algs.len() > 2 {
            Some(AlgorithmIdentifierOwned::from_der(&cp.signing_algs[2]).unwrap())
        } else {
            None
        };

        let mut params = vec![spki_alg1, spki_alg2];
        if let Some(s) = spki_alg3 {
            params.push(s);
        }

        let enc_params = params.to_vec().unwrap();

        //only doing ECDSA and Diluthium3 for the moment
        let signing_algorithm = AlgorithmIdentifierOwned {
            oid: s_alg,
            parameters: Some(Any::from_der(enc_params.as_slice()).unwrap()),
        };
        cp.signing_algs.push(signing_algorithm.to_vec().unwrap());
    }

    cp
}

pub fn generate_signature(
    spki_algorithm: &ObjectIdentifier,
    signing_key_bytes: &[u8],
    tbs_cert: &[u8],
) -> Vec<u8> {
    let s = if is_diluthium2(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium2::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium3(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium3::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium5(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium5::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium2aes(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium2aes::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium3aes(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium3aes::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium5aes(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium5aes::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_falcon512(spki_algorithm) {
        // let (pk, sk) = falcon512::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = falcon512::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_falcon1024(spki_algorithm) {
        // let (pk, sk) = falcon1024::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = falcon1024::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128f_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256128frobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128frobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128f_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256128fsimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128fsimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128s_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256128srobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128srobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128s_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256128ssimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128ssimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192f_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256192frobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192frobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192f_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256192fsimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192fsimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192s_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256192srobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192srobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192s_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256192ssimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192ssimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256f_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256256frobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256frobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256f_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256256fsimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256fsimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256s_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256256srobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256srobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256s_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256256ssimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256ssimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_ecdsa(spki_algorithm) {
        let signing_key = SigningKey::from_bytes(signing_key_bytes).unwrap();

        let ecsignature: Signature = signing_key.sign(tbs_cert);
        let derecsignature = ecsignature.to_der();
        derecsignature.as_bytes().to_vec()
    } else {
        panic!()
    };
    s
}

/// Generate a self signed certificate containing the given name, public key and extensions
#[allow(clippy::too_many_arguments)]
pub fn generate_signed(
    _args: &CertGenArgs,
    spkibuf: &[u8],
    issuer: &Name,
    subject: &Name,
    extensions: Option<Extensions>,
    cp: &CompositeParts,
    sub_cp: &CompositeParts,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);
    serial[0] = 0x01;
    let serial_number = SerialNumber::new(&serial).unwrap();

    // TODO
    let spki = SubjectPublicKeyInfoOwned::from_der(spkibuf).unwrap();

    let ten_years_duration = Duration::from_secs(365 * 24 * 60 * 60 * 10);
    let ten_years_time = SystemTime::now().checked_add(ten_years_duration).unwrap();

    let validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_unix_duration(SystemTime::now().duration_since(UNIX_EPOCH).unwrap())
                .unwrap(),
        ),
        not_after: Time::UtcTime(
            UtcTime::from_unix_duration(ten_years_time.duration_since(UNIX_EPOCH).unwrap())
                .unwrap(),
        ),
    };

    let signature_alg =
        AlgorithmIdentifierOwned::from_der(cp.signing_algs.last().unwrap()).unwrap();
    let tbs_certificate = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: signature_alg.clone(),
        issuer: issuer.clone(),
        validity,
        subject: subject.clone(),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions,
    };

    let tbs_cert = match tbs_certificate.to_vec() {
        Ok(tbs_cert) => tbs_cert,
        Err(e) => return Err(e),
    };

    let spki_alg1 = AlgorithmIdentifierOwned::from_der(&cp.spki_algs[0]).unwrap();
    let signing_alg_last =
        AlgorithmIdentifierOwned::from_der(cp.signing_algs.last().unwrap()).unwrap();

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

        let mut sig = vec![
            BitString::from_bytes(s1.as_slice()).unwrap(),
            BitString::from_bytes(s2.as_slice()).unwrap(),
        ];
        if cp.signing_keys.len() > 2 {
            let spki_alg3 = AlgorithmIdentifierOwned::from_der(&cp.spki_algs[2]).unwrap();

            let s3 = generate_signature(
                &spki_alg3.oid,
                cp.signing_keys[2].as_slice(),
                tbs_cert.as_slice(),
            );
            sig.push(BitString::from_bytes(s3.as_slice()).unwrap());
        }
        sig.to_vec().unwrap()
    } else {
        generate_signature(
            &spki_alg1.oid,
            cp.signing_keys[0].as_slice(),
            tbs_cert.as_slice(),
        )
    };

    let signature = BitString::from_bytes(s.as_slice()).unwrap();

    let c = Certificate {
        tbs_certificate,
        signature_algorithm: signing_alg_last.clone(),
        signature,
    };

    let tbs_crl = TbsCertList {
        version: Version::V3,
        signature: signature_alg,
        issuer: subject.clone(),
        this_update: validity.not_before,
        next_update: Some(validity.not_after),
        revoked_certificates: None,
        crl_extensions: None,
    };

    let tbs_cert_list = match tbs_crl.to_vec() {
        Ok(tbs_cert) => tbs_cert,
        Err(e) => return Err(e),
    };

    let s_crl = if sub_cp.signing_keys.len() > 1 {
        let s1 = generate_signature(
            &spki_alg1.oid,
            sub_cp.signing_keys[0].as_slice(),
            tbs_cert_list.as_slice(),
        );

        let spki_alg2 = AlgorithmIdentifierOwned::from_der(&sub_cp.signing_algs[1]).unwrap();
        let s2 = generate_signature(
            &spki_alg2.oid,
            sub_cp.signing_keys[1].as_slice(),
            tbs_cert_list.as_slice(),
        );

        let mut sig = vec![
            BitString::from_bytes(s1.as_slice()).unwrap(),
            BitString::from_bytes(s2.as_slice()).unwrap(),
        ];
        if cp.signing_keys.len() > 2 {
            let spki_alg3 = AlgorithmIdentifierOwned::from_der(&cp.spki_algs[2]).unwrap();

            let s3 = generate_signature(
                &spki_alg3.oid,
                sub_cp.signing_keys[2].as_slice(),
                tbs_cert_list.as_slice(),
            );
            sig.push(BitString::from_bytes(s3.as_slice()).unwrap());
        }

        sig.to_vec().unwrap()
    } else {
        generate_signature(
            &spki_alg1.oid,
            sub_cp.signing_keys[0].as_slice(),
            tbs_cert_list.as_slice(),
        )
    };
    let signature_crl = BitString::from_bytes(s_crl.as_slice()).unwrap();

    let crl = CertificateList {
        tbs_cert_list: tbs_crl,
        signature_algorithm: signing_alg_last,
        signature: signature_crl,
    };

    Ok((c.to_vec().unwrap(), crl.to_vec().unwrap()))
}

pub fn generate_leaf_cert(args: &CertGenArgs, cap: &Vec<CompanyAndProducts>) {
    // Generate a fresh key using args to determine whether to generate composite
    let cp = generate_keypairs(args);
    let skid = OctetStringRef::new(cp.skids.last().unwrap().as_slice()).unwrap();

    let mut rng = rand::thread_rng();
    let company = &cap[rng.gen_range(0..cap.len())];
    let strdn = format!(
        "C=US,O=PQC Test,CN={}",
        company.company.replace(", Inc.", "\\, Inc.")
    );
    let enc_dn = encode_dn_from_string(strdn.as_str()).unwrap();
    let subject = Name::from_der(enc_dn.as_slice()).unwrap();

    let mut issuer = Name::from_der(enc_dn.as_slice()).unwrap();
    if args.generate_ca_signed_certs {
        issuer = Name::from_der(company.ca_name.as_slice()).unwrap();
    }

    // key usage, basic constraints, eku
    let ku = KeyUsage(KeyUsages::NonRepudiation | KeyUsages::DigitalSignature);
    let enc_ku = ku.to_vec().unwrap();
    let eku = vec![ID_KP_CLIENT_AUTH];
    let enc_eku = eku.to_vec().unwrap();
    let bc = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    };
    let enc_bc = bc.to_vec().unwrap();

    let ext2 = Extension {
        extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
        critical: false,
        extn_value: OctetString::new(skid.as_bytes()).unwrap(),
    };

    let ext3 = Extension {
        extn_id: ID_CE_KEY_USAGE,
        critical: false,
        extn_value: OctetString::new(enc_ku.as_slice()).unwrap(),
    };

    let ext4 = Extension {
        extn_id: ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: OctetString::new(enc_bc.as_slice()).unwrap(),
    };

    let ext5 = Extension {
        extn_id: ID_CE_EXT_KEY_USAGE,
        critical: false,
        extn_value: OctetString::new(enc_eku.as_slice()).unwrap(),
    };

    let ext6 = Extension {
        extn_id: ID_CE_AUTHORITY_KEY_IDENTIFIER,
        critical: false,
        extn_value: OctetString::new(company.ca_cp.skids.last().unwrap().as_slice()).unwrap(),
    };

    let extensions = vec![ext2, ext3, ext4, ext5, ext6];

    if args.generate_self_signed_certs {
        let (enc_sscert, _enc_crl) = if args.generate_ca_signed_certs {
            generate_signed(
                args,
                cp.spkis.last().unwrap().clone().as_slice(),
                &issuer,
                &subject,
                Some(extensions.clone()),
                &company.ca_cp,
                &cp,
            )
        } else {
            generate_signed(
                args,
                cp.spkis.last().unwrap().as_slice(),
                &issuer,
                &subject,
                Some(extensions.clone()),
                &cp,
                &cp,
            )
        }
        .unwrap();

        let enc_oak_leaf = if cp.signing_keys.len() > 1 {
            let private_key_alg = AlgorithmIdentifierOwned::from_der(&cp.signing_algs[0]).unwrap();
            let oak_leaf = OneAsymmetricKey {
                version: pqckeys::oak::Version::V2,
                private_key_alg,
                private_key: OctetString::new(cp.signing_keys[0].as_slice()).unwrap(),
                attributes: None,
                public_key: None,
            };
            let private_key_alg2 = AlgorithmIdentifierOwned::from_der(&cp.signing_algs[1]).unwrap();
            let oak_leaf2 = OneAsymmetricKey {
                version: pqckeys::oak::Version::V2,
                private_key_alg: private_key_alg2,
                private_key: OctetString::new(cp.signing_keys[1].as_slice()).unwrap(),
                attributes: None,
                public_key: None,
            };
            let oaks = vec![oak_leaf, oak_leaf2];
            oaks.to_vec().unwrap()
        } else {
            let private_key_alg = AlgorithmIdentifierOwned::from_der(&cp.signing_algs[0]).unwrap();
            let oak_leaf = OneAsymmetricKey {
                version: pqckeys::oak::Version::V2,
                private_key_alg,
                private_key: OctetString::new(cp.signing_keys[0].as_slice()).unwrap(),
                attributes: None,
                public_key: None,
            };
            oak_leaf.to_vec().unwrap()
        };

        if let Some(folder) = &args.self_signed_certs_folder {
            let p = Path::new(folder.as_str());
            //TODO temp
            //let f = p.join(Path::new(format!("{}_{}.der", name, iteration).as_str()));
            let f = p.join(Path::new("cert.der"));
            match fs::write(&f, &enc_sscert) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "Failed to write self-signed certificate to {:?} with error:",
                        e
                    );
                }
            }
            let label = "CERTIFICATE";
            let encoded =
                pem_rfc7468::encode_string(label, LineEnding::LF, enc_sscert.as_slice()).unwrap();
            let p = Path::new(folder.as_str());
            let f = p.join(Path::new("cert.pem"));
            match fs::write(&f, encoded) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "Failed to write self-signed certificate to {:?} with error:",
                        e
                    );
                }
            }
            let p = Path::new(folder.as_str());
            //let f = p.join(Path::new(format!("{}_{}.oak", name, iteration).as_str()));
            let f = p.join(Path::new("cert_priv.der"));
            match fs::write(&f, &enc_oak_leaf) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "Failed to write self-signed certificate to {:?} with error:",
                        e
                    );
                }
            }
            let label = "PRIVATE KEY";
            let encoded =
                pem_rfc7468::encode_string(label, LineEnding::LF, enc_oak_leaf.as_slice()).unwrap();
            let p = Path::new(folder.as_str());
            let f = p.join(Path::new("cert_priv.pem"));
            match fs::write(&f, encoded) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "Failed to write self-signed certificate to {:?} with error:",
                        e
                    );
                }
            }
        } else {
            let hex = hex::encode_upper(enc_sscert);
            println!(
                "Self-signed certificate: {}",
                std::str::from_utf8(hex.as_slice()).unwrap()
            );
        }
    }

    if args.generate_csrs {
        let enc_req = generate_csr(
            cp.spkis.last().unwrap().as_slice(),
            &subject,
            Some(extensions),
            &cp,
        )
        .unwrap();

        if let Some(folder) = &args.csrs_folder {
            let p = Path::new(folder.as_str());
            //let f = p.join(Path::new(format!("{}.csr", iteration).as_str()));
            let f = p.join(Path::new("cert.csr"));
            match fs::write(&f, enc_req) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "Failed to write self-signed certificate to {:?} with error:",
                        e
                    );
                }
            }
        } else {
            let hex = hex::encode_upper(enc_req);
            println!("CSR: {}", std::str::from_utf8(hex.as_slice()).unwrap());
        }
    }
}

pub fn generate_ca_cert(
    args: &CertGenArgs,
    sk: &CompositeParts,
    enc_iss_dn: &Vec<u8>,
    enc_sub_dn: &Vec<u8>,
    akid: &Vec<u8>,
) -> (CompositeParts, Vec<u8>, Vec<u8>) {
    let cp = generate_keypairs(args);
    let skid = OctetStringRef::new(cp.skids.last().unwrap().as_slice()).unwrap();
    let issuer = Name::from_der(enc_iss_dn.as_slice()).unwrap();
    let subject = Name::from_der(enc_sub_dn.as_slice()).unwrap();

    // key usage, basic constraints, eku
    let ku = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature);
    let enc_ku = ku.to_vec().unwrap();

    let bc = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    let enc_bc = bc.to_vec().unwrap();
    let ext2 = Extension {
        extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
        critical: false,
        extn_value: OctetString::new(skid.as_bytes()).unwrap(),
    };

    let ext3 = Extension {
        extn_id: ID_CE_KEY_USAGE,
        critical: false,
        extn_value: OctetString::new(enc_ku.as_slice()).unwrap(),
    };

    let ext4 = Extension {
        extn_id: ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: OctetString::new(enc_bc.as_slice()).unwrap(),
    };
    let ext5 = Extension {
        extn_id: ID_CE_AUTHORITY_KEY_IDENTIFIER,
        critical: false,
        extn_value: OctetString::new(akid.as_slice()).unwrap(),
    };

    let extensions = vec![ext2, ext3, ext4, ext5];

    let (enc_sscert, enc_crl) = generate_signed(
        args,
        cp.spkis.last().unwrap().as_slice(),
        &issuer,
        &subject,
        Some(extensions),
        sk,
        &cp,
    )
    .unwrap();

    (cp, enc_sscert, enc_crl)
}

pub fn generate_root_cert(
    args: &CertGenArgs,
    enc_dn: &Vec<u8>,
) -> (CompositeParts, Vec<u8>, Vec<u8>, Vec<u8>) {
    let cp = generate_keypairs(args);
    let skid = OctetStringRef::new(cp.skids.last().unwrap().as_slice()).unwrap();
    let subject = Name::from_der(enc_dn.as_slice()).unwrap();

    // key usage, basic constraints, eku
    let ku = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature);
    let enc_ku = ku.to_vec().unwrap();

    let bc = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    let enc_bc = bc.to_vec().unwrap();
    let ext2 = Extension {
        extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
        critical: false,
        extn_value: OctetString::new(skid.as_bytes()).unwrap(),
    };

    let ext3 = Extension {
        extn_id: ID_CE_KEY_USAGE,
        critical: false,
        extn_value: OctetString::new(enc_ku.as_slice()).unwrap(),
    };

    let ext4 = Extension {
        extn_id: ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: OctetString::new(enc_bc.as_slice()).unwrap(),
    };

    let extensions = vec![ext2, ext3, ext4];

    let (enc_sscert, enc_crl) = generate_signed(
        args,
        cp.spkis.last().unwrap().as_slice(),
        &subject,
        &subject,
        Some(extensions),
        &cp,
        &cp,
    )
    .unwrap();

    let skid_value = OctetString::from_der(skid.as_bytes()).unwrap();

    let akid = AuthorityKeyIdentifier {
        key_identifier: Some(skid_value),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };

    let enc_akid = akid.to_vec().unwrap();
    (cp, enc_sscert, enc_crl, enc_akid)
}

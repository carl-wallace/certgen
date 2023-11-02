//! Utilities to support self-signed certificate and CSR generation

use std::fs;
use std::path::Path;

use names::Generator;
use rand::Rng;

use certval::encode_dn_from_string;
use der::asn1::OctetString;
use der::pem::LineEnding;
use der::{Decode, Encode};
use pqckeys::oak::{OneAsymmetricKey, Version};
use spki::AlgorithmIdentifier;

use crate::certs_pqc::CompositeParts;
use crate::{generate_ca_cert, generate_root_cert, CertGenArgs, CompanyAndProducts};

/// Capitalizes the first character in s.
pub fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Generate random company name
fn gen_name(gen_company: bool) -> String {
    let mut generator = Generator::default();
    let name = generator.next().unwrap();
    let pieces = name.split('-');
    let mut final_name = String::with_capacity(name.len() + 6);
    let mut b = false;
    for p in pieces {
        final_name.push_str(capitalize(p).as_str());

        if !b {
            final_name.push(' ');
            b = true;
        } else if gen_company {
            final_name.push_str(", Inc.");
        }
    }
    final_name
}

/// Return random true or false value
pub fn true_or_false() -> bool {
    let mut rng = rand::thread_rng();
    0 == rng.gen_range(0..2)
}

/// Generate set of random companies with random products
#[allow(clippy::too_many_arguments)]
pub fn gen_companies_and_products(
    args: &CertGenArgs,
    sk: &CompositeParts,
    enc_iss_dn: &[u8],
    enc_iss_skid: &[u8],
    sk_ca: &CompositeParts,
    enc_iss_ca_dn: &[u8],
) -> Vec<CompanyAndProducts> {
    let mut rng = rand::thread_rng();
    let mut cap = vec![];
    let mut per_company_ta = args.per_company_ta;
    let mut per_company_ca = args.per_company_ca;

    for _ in 0..args.num_companies {
        if args.random_infrastructure {
            per_company_ca = true_or_false();
            per_company_ta = true_or_false();
        }

        let company = gen_name(true);

        let n = company.replace(", Inc.", "\\, Inc.");
        let name = company.replace(", Inc.", "");

        let mut enc_ta_dn = enc_iss_dn.to_owned();
        let mut enc_ca_dn = enc_iss_ca_dn.to_owned();
        let mut ta_sk = sk.clone();
        let mut ca_sk = sk_ca.clone();
        let mut ta_skid = enc_iss_skid.to_owned();

        if per_company_ta {
            let str_ta_dn = format!("C=US,O={},CN={} Trust Anchor", n, n);
            enc_ta_dn = encode_dn_from_string(str_ta_dn.as_str()).unwrap();

            let (root_sk, root_cert, root_crl, skid) = generate_root_cert(args, &enc_ta_dn);
            ta_sk = root_sk;
            ta_skid = skid;

            if let Some(folder) = &args.self_signed_certs_folder {
                let p = Path::new(folder.as_str());
                let f = p.join(Path::new(format!("{}_ta.der", name).as_str()));
                match fs::write(f, root_cert) {
                    Ok(_) => {}
                    Err(e) => {
                        println!(
                            "Failed to write self-signed certificate to {:?} with error:",
                            e
                        );
                    }
                }
                let p = Path::new(folder.as_str());
                let f = p.join(Path::new(format!("{}_ta.crl", name).as_str()));
                match fs::write(f, root_crl) {
                    Ok(_) => {}
                    Err(e) => {
                        println!(
                            "Failed to write self-signed certificate to {:?} with error:",
                            e
                        );
                    }
                }
            }
            per_company_ca = true;
        }

        if per_company_ca {
            let str_ca_dn = format!("C=US,O={},CN={} Certification Authority", n, n);
            enc_ca_dn = encode_dn_from_string(str_ca_dn.as_str()).unwrap();

            let (ca_key, ca_cert, ca_crl) =
                generate_ca_cert(args, &ta_sk.clone(), &enc_ta_dn, &enc_ca_dn, &ta_skid);
            ca_sk = ca_key;

            if args.generate_ca_signed_certs && per_company_ca {
                if let Some(folder) = &args.self_signed_certs_folder {
                    let p = Path::new(folder.as_str());
                    let f = p.join(Path::new(format!("{}_ca.der", name).as_str()));
                    match fs::write(f, ca_cert) {
                        Ok(_) => {}
                        Err(e) => {
                            println!(
                                "Failed to write self-signed certificate to {:?} with error:",
                                e
                            );
                        }
                    }
                    let p = Path::new(folder.as_str());
                    let f = p.join(Path::new(format!("{}_ca.crl", name).as_str()));
                    match fs::write(f, ca_crl) {
                        Ok(_) => {}
                        Err(e) => {
                            println!(
                                "Failed to write self-signed certificate to {:?} with error:",
                                e
                            );
                        }
                    }
                }
            }
        }

        let mut c = CompanyAndProducts {
            company,
            products: vec![],
            ca_name: enc_ca_dn,
            root_cp: ta_sk,
            ca_cp: ca_sk,
        };

        for _ in 0..rng.gen_range(1..(args.max_products_per_company + 1)) {
            c.products.push(gen_name(false));
        }
        cap.push(c);
    }
    cap.clone()
}

pub fn generate_shared_ca_and_ta(
    args: &CertGenArgs,
) -> (CompositeParts, Vec<u8>, Vec<u8>, CompositeParts, Vec<u8>) {
    let enc_ta_dn = encode_dn_from_string(args.shared_ta_name.as_str()).unwrap();
    let (shared_root_cp, shared_root_cert, shared_root_crl, shared_root_skid) =
        generate_root_cert(args, &enc_ta_dn);
    let private_key_alg_ta = AlgorithmIdentifier::from_der(&shared_root_cp.spki_algs[0]).unwrap();
    let enc_oak_ta = if shared_root_cp.signing_keys.len() > 1 {
        let oak_leaf = OneAsymmetricKey {
            version: pqckeys::oak::Version::V2,
            private_key_alg: private_key_alg_ta.clone(),
            private_key: OctetString::new(shared_root_cp.signing_keys[0].as_slice()).unwrap(),
            attributes: None,
            public_key: None,
        };
        let private_key_alg_ta2 =
            AlgorithmIdentifier::from_der(&shared_root_cp.spki_algs[1]).unwrap();
        let oak_leaf2 = OneAsymmetricKey {
            version: pqckeys::oak::Version::V2,
            private_key_alg: private_key_alg_ta2,
            private_key: OctetString::new(shared_root_cp.signing_keys[1].as_slice()).unwrap(),
            attributes: None,
            public_key: None,
        };
        let oaks = vec![oak_leaf, oak_leaf2];
        oaks.to_der().unwrap()
    } else {
        let oak_ta = OneAsymmetricKey {
            version: Version::V2,
            private_key_alg: private_key_alg_ta.clone(),
            private_key: OctetString::new(shared_root_cp.signing_keys[0].as_slice()).unwrap(),
            attributes: None,
            public_key: None,
        };
        oak_ta.to_der().unwrap()
    };

    let enc_ca_dn = encode_dn_from_string(args.shared_ca_name.as_str()).unwrap();
    let (shared_ca_cp, shared_ca_cert, shared_ca_crl) = generate_ca_cert(
        args,
        &shared_root_cp,
        &enc_ta_dn,
        &enc_ca_dn,
        &shared_root_skid,
    );
    let private_key_alg_ca = AlgorithmIdentifier::from_der(&shared_ca_cp.spki_algs[0]).unwrap();
    let enc_oak_ca = if shared_ca_cp.signing_keys.len() > 1 {
        let oak_leaf = OneAsymmetricKey {
            version: pqckeys::oak::Version::V2,
            private_key_alg: private_key_alg_ca,
            private_key: OctetString::new(shared_ca_cp.signing_keys[0].as_slice()).unwrap(),
            attributes: None,
            public_key: None,
        };
        let private_key_alg_ca2 =
            AlgorithmIdentifier::from_der(&shared_ca_cp.spki_algs[1]).unwrap();
        let oak_leaf2 = OneAsymmetricKey {
            version: pqckeys::oak::Version::V2,
            private_key_alg: private_key_alg_ca2,
            private_key: OctetString::new(shared_ca_cp.signing_keys[1].as_slice()).unwrap(),
            attributes: None,
            public_key: None,
        };
        let oaks = vec![oak_leaf, oak_leaf2];
        oaks.to_der().unwrap()
    } else {
        let oak_ta = OneAsymmetricKey {
            version: Version::V2,
            private_key_alg: private_key_alg_ta,
            private_key: OctetString::new(shared_ca_cp.signing_keys[0].as_slice()).unwrap(),
            attributes: None,
            public_key: None,
        };
        oak_ta.to_der().unwrap()
    };

    if let Some(folder) = &args.self_signed_certs_folder {
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ta.der"));
        match fs::write(f, &shared_root_cert) {
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
            pem_rfc7468::encode_string(label, LineEnding::LF, shared_root_cert.as_slice()).unwrap();
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ta.pem"));
        match fs::write(f, encoded) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write self-signed certificate to {:?} with error:",
                    e
                );
            }
        }
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ta.oak"));
        match fs::write(f, &enc_oak_ta) {
            Ok(_) => {}
            Err(e) => {
                println!("Failed to write TA signing key to {:?} with error:", e);
            }
        }
        let label = "PRIVATE KEY";
        let encoded =
            pem_rfc7468::encode_string(label, LineEnding::LF, enc_oak_ta.as_slice()).unwrap();
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("ta_priv.pem"));
        match fs::write(f, encoded) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write self-signed certificate to {:?} with error:",
                    e
                );
            }
        }
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ta.crl"));
        match fs::write(f, shared_root_crl) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write self-signed certificate to {:?} with error:",
                    e
                );
            }
        }
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ca.der"));
        match fs::write(f, &shared_ca_cert) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write self-signed certificate to {:?} with error:",
                    e
                );
            }
        }
        let encoded =
            pem_rfc7468::encode_string(label, LineEnding::LF, shared_ca_cert.as_slice()).unwrap();
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ca.pem"));
        match fs::write(f, encoded) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write self-signed certificate to {:?} with error:",
                    e
                );
            }
        }
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ca.oak"));
        match fs::write(f, &enc_oak_ca) {
            Ok(_) => {}
            Err(e) => {
                println!("Failed to write CA signing key to {:?} with error:", e);
            }
        }
        let label = "PRIVATE KEY";
        let encoded =
            pem_rfc7468::encode_string(label, LineEnding::LF, enc_oak_ca.as_slice()).unwrap();
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ca_priv.pem"));
        match fs::write(f, encoded) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write self-signed certificate to {:?} with error:",
                    e
                );
            }
        }
        let p = Path::new(folder.as_str());
        let f = p.join(Path::new("shared_ca.crl"));
        match fs::write(f, shared_ca_crl) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write self-signed certificate to {:?} with error:",
                    e
                );
            }
        }
    }
    (
        shared_root_cp,
        enc_ta_dn,
        shared_root_skid,
        shared_ca_cp,
        enc_ca_dn,
    )
}

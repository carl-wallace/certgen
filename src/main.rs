//! Test utility for generating certs and CSRs that use PQC algorithms

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod certs_pqc;
mod csrs;
mod utils;

use std::time::Instant;

use clap::CommandFactory;
use clap::Parser;

use crate::certs_pqc::{generate_ca_cert, generate_leaf_cert, generate_root_cert, CompositeParts};
use crate::utils::{gen_companies_and_products, generate_shared_ca_and_ta};

/// Arguments for test generator for self-signed certificates and CSRs that use PQC algorithms. The
/// primary purpose of the tool is to generate artifacts in bulk using a variety of names. The
///
///
/// Typical usage is as follows. The -s argument provides a destination for certificates. The -c
/// argument provides a destination for CSRs. The --generate-ca-signed-certs causes certificates to
/// be signed by a superior CA (except for root certificates). The -n, -m and -i arguments limit the
/// number of companies, products per company and certificates/CSRs per company. The --pk-alg1 and
/// --sig-alg1 arguments establish which algorithms to use when generating keys and signatures.
///
/// ```text
/// certgen -s /somepath/certs -c /somepath/csrs --generate-ca-signed-certs -n 2 -m 2 -i 2
///   --pk-alg1 1.3.9999.6.4.1 --sig-alg1 1.3.9999.6.4.1
/// ```
/// Usage when targeting composite keys is more verbose. The pk-alg2 and sig-alg2 establish which
/// algorithms to use for the second key pair in a composite set (only two key pairs are supported
/// at present). The --composite-pk and --composite-sig arguments establish the values that signal
/// a composite key or signature is in use.
///
/// ```text
/// certgen -s /somepath/certs -c /somepath/csrs --generate-ca-signed-certs -n 2 -m 2 -i 2
///   --pk-alg1 1.2.840.10045.3.1.7 --sig-alg1 1.2.840.10045.4.3.2
///   --pk-alg2 1.3.6.1.4.1.2.267.7.4.5 --sig-alg2 1.3.6.1.4.1.2.267.7.4.5
///   --composite-pk 1.3.6.1.4.1.18227.2.2 --composite-sig 1.3.6.1.4.1.18227.2.1
/// ```
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct CertGenArgs {
    /// Number of fake company names to generate
    #[clap(short, long, default_value_t = 255)]
    pub num_companies: u16,

    /// Max number of products to assign to each company
    #[clap(short, long, default_value_t = 10)]
    pub max_products_per_company: u16,

    /// Full path and filename of folder to receive generated binary DER-encoded self-signed certificates.
    /// If not specified, hex is written to stdout.  When specified, generate_self_signed_certs is automatically set to true.
    #[clap(long, short)]
    pub self_signed_certs_folder: Option<String>,

    /// Full path and filename of folder to receive generated binary DER-encoded CSRs. If not specified,
    /// hex is written to stdout. When specified, generate_csrs is automatically set to true.
    #[clap(long, short)]
    pub csrs_folder: Option<String>,

    /// Number of CSRs and/or self-signed certificates to generate.
    #[clap(short, long, default_value_t = 1000)]
    pub iterations: i32,

    /// Generate a self-signed certificate each iteration.
    #[clap(long)]
    pub generate_self_signed_certs: bool,

    /// Generate a CA-signed certificate each iteration (dominates generate_self_signed_certs).
    #[clap(long)]
    pub generate_ca_signed_certs: bool,

    /// Use per-company CA when generating CA-signed certificate each iteration.
    #[clap(long)]
    pub per_company_ca: bool,

    /// Use per-company TA when generating per-company CA certificates (when true implies per_company_ca is true).
    #[clap(long)]
    pub per_company_ta: bool,

    /// Use random values for per_company_ca and per_company_ta (dominates specified values)
    #[clap(long)]
    pub random_infrastructure: bool,

    /// Generate a CSR each iteration.
    #[clap(long)]
    pub generate_csrs: bool,

    /// Generate composite certificates using indicated object identifier for public keys
    #[clap(long)]
    pub composite_pk: Option<String>,

    /// Generate composite certificates using indicated object identifier for signatures
    #[clap(long)]
    pub composite_sig: Option<String>,

    /// Object identifier indicating type of public key. For EC algs, this is the value that is
    /// encoded in the parameters field (with 1.2.840.10045.2.1 used as the algorithm).
    #[clap(long, default_value = "1.2.840.10045.3.1.7")]
    pub pk_alg1: String,
    /// Object identifier indicating the signature algorithm.
    #[clap(long, default_value = "1.2.840.10045.4.3.2")]
    pub sig_alg1: String,

    /// Object identifier indicating type of public key for the second key in a composite.
    /// For EC algs, this is the value that is encoded in the parameters field (with
    /// 1.2.840.10045.2.1 used as the algorithm). Only used when composite is true.
    #[clap(long)]
    pub pk_alg2: Option<String>,
    /// Object identifier indicating the signature algorithm for the second key in a composite.
    /// Only used when composite is true.
    #[clap(long)]
    pub sig_alg2: Option<String>,

    /// Object identifier indicating type of public key for the second key in a composite.
    /// For EC algs, this is the value that is encoded in the parameters field (with
    /// 1.2.840.10045.2.1 used as the algorithm). Only used when composite is true.
    #[clap(long)]
    pub pk_alg3: Option<String>,
    /// Object identifier indicating the signature algorithm for the second key in a composite.
    /// Only used when composite is true.
    #[clap(long)]
    pub sig_alg3: Option<String>,

    /// Subject name for shared CA certificate.
    #[clap(
        long,
        default_value = "C=US,O=Example,CN=Example Certification Authority"
    )]
    pub shared_ca_name: String,

    /// Subject name for shared TA certificate.
    #[clap(long, default_value = "C=US,O=Example,CN=Example Trust Anchor")]
    pub shared_ta_name: String,
}

/// Randomly generated company name and corresponding products
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanyAndProducts {
    /// name of company
    pub company: String,
    /// vector of product names
    pub products: Vec<String>,
    /// company CA subject name
    pub ca_name: Vec<u8>,
    /// company root composite parts
    pub root_cp: CompositeParts,
    /// company CA composite parts
    pub ca_cp: CompositeParts,
}

fn main() {
    let mut args = CertGenArgs::parse();
    if args.self_signed_certs_folder.is_some() && !args.generate_self_signed_certs {
        args.generate_self_signed_certs = true;
    }
    if args.csrs_folder.is_some() && !args.generate_csrs {
        args.generate_csrs = true;
    }
    if !args.generate_csrs && !args.generate_self_signed_certs {
        let mut a = CertGenArgs::command();
        if let Err(_e) = a.print_help() {
            println!("Error printing help. Try again with -h parameter.")
        }
        return;
    }

    // Generate a TA and a CA to be used with CompanyAndProducts instances that do not use a per-company CA and TA.
    let (shared_root_cp, enc_ta_dn, shared_root_skid, shared_ca_cp, enc_ca_dn) =
        generate_shared_ca_and_ta(&args);

    // generate a collection of fake companies, products and TAs/CAs
    let cap = gen_companies_and_products(
        &args,
        &shared_root_cp,
        &enc_ta_dn,
        &shared_root_skid,
        &shared_ca_cp,
        &enc_ca_dn,
    );
    // generate a collection of CSRs and leaf certificates
    let start = Instant::now();
    for _ in 0..args.iterations {
        generate_leaf_cert(&args, &cap);
    }
    let duration = start.elapsed();
    let dsecs = duration.as_millis();
    println!(
        "{} iterations took {}ms; {} on average",
        args.iterations,
        dsecs,
        dsecs / (args.iterations as u128)
    );
}

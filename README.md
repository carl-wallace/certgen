# certgen

Quick and dirty utility for generating artifacts for the [IETF 115 PQC hackathon](https://github.com/IETF-Hackathon/pqc-certificates). 

This tool uses a PQC-focused branch of a [fork](https://github.com/carl-wallace/formats/tree/pqc) of the [RustCrypto formats](https://github.com/RustCrypto/formats) repo that includes support for PQ-related structures and a branch with
PQ-focused changes for the [certval library and pittv3 utility](https://github.com/carl-wallace/rust-pki/tree/pqc).

The pqtests.sh script can be used to generate artifacts or to verify artifacts that follow the format defined for the [IETF 115 PQC hackathon](https://github.com/IETF-Hackathon/pqc-certificates) repo.
For artifact collections that lack (current) revocation information, place a file named `default.json` containing the following JSON at the root of the folder containing the artifacts.

```json
{"psCheckRevocationStatus":{"Bool":false}}
```

The script assumes `certgen` is located in the `./target/release` folder and that `pittv3` is located in the `../rust-pki/target/release/` folder.
If the binaries are located elsewhere edit lines 35 and/or 36 the script accordingly.

To generate artifacts, run the script with no parameters. A folder named `artifacts` will be generated and populated. To verify artifacts,
run the script with the path to the folder containing the artifacts as a parameter. Note, pittv3 will attempt to verify all
files with a .der extension in the artifacts folder. Unfortunately, the naming scheme features private key files named
with .der. For best results, delete files with "_priv.oak" or "_priv.pem" before validating a folder containing artifacts.

The default `log.yaml` file writes a large volume of data to the console. Edit it to avoid this. See [log4rs](https://docs.rs/log4rs/1.2.0/log4rs/)
documentation for details on the file format.

Note, the tool does very little error handling.

## License

All crates licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"
[deps-image]: https://deps.rs/repo/github/RustCrypto/formats/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/formats

[//]: # "links"
[itu x.660]: https://www.itu.int/rec/T-REC-X.660
[itu x.690]: https://www.itu.int/rec/T-REC-X.690
[rfc 4716]: https://datatracker.ietf.org/doc/html/rfc4253
[rfc 5208]: https://datatracker.ietf.org/doc/html/rfc5208
[rfc 5280 section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
[rfc 5280]: https://datatracker.ietf.org/doc/html/rfc5280
[rfc 5652]: https://datatracker.ietf.org/doc/html/rfc5652
[rfc 5958]: https://datatracker.ietf.org/doc/html/rfc5958
[rfc 8017]: https://datatracker.ietf.org/doc/html/rfc8017
[rfc 8018]: https://datatracker.ietf.org/doc/html/rfc8018
[rfc 8933]: https://datatracker.ietf.org/doc/html/rfc8933
[rfc 8446 section 3]: https://datatracker.ietf.org/doc/html/rfc8446#section-3
[sec1: elliptic curve cryptography]: https://www.secg.org/sec1-v2.pdf

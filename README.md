# Repository for the project of the course NT230 - Cryptography

## About this repository:
This repo includes the sources for 2 new post-quantum cryptography standards:
  - FIPS 203: Module-Lattice-Based Key Encapsulation Mechanism Standard
  - FIPS 204: Module-Lattice-Based Digital Signature Standard

## References:
  - FIPS 203: https://csrc.nist.gov/pubs/fips/203/ipd
  - FIPS 204: https://csrc.nist.gov/pubs/fips/204/ipd

## Dependencies:
- `pycryptodome`
- `pwntools`
- `tk`
- `tkthread`

## How to use this repository
* Inside the repo, there are python sources implementing two new cryptographic standards: FIPS 203 and FIPS 204.
* The main file for ML-KEM is `ml_kem.py` and the main file for ML-DSA is `ml_dsa.py`. Other files are supporting components, respectively.
* Running `ML-KEM.py` performs a small test on the scheme. It will simply create key pair, encapsulate secret and decapsulate it. If nothing goes wrong, both parties should have the same secret, indicating that the ML-KEM works properly.
* For ML-DSA, the file has been written to be a simple CLI, where we can create keys for ML-DSA and use it to sign and verify files.
* Moreover, there are two files `client.py` and `server.py` written to showcase a simple messaging application using those two schemes.
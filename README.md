# Repository for the project of the course NT230 - Cryptography

## About this repository:
This repo includes the source of 2 new post-quantum cryptography standards:
  - FIPS 203: Module-Lattice-Based Key Encapsulation Mechanism Standard
  - FIPS 204: Module-Lattice-Based Digital Signature Standard

## Dependencies:
#### For python:
- `pycryptodome`
#### For C++:
- TBA

### How to use this repository
- Up to the time that this readme was written, there were only python sources for FIPS 203, implementing ML-KEM.
- The main file for ML-KEM is `ml_kem.py`. Others are supporting components.
- Running `ml_kem.py` will run a simple test on the implementation, by simply creating key pair, encapsulating secret and decapsulating it. If nothing goes wrong, both parties should have the same secret, indicating that the ML-KEM works properly.
# Double Rainbow: Fault Analysis of Rainbow PQC Signature Scheme in Unicorn based Rainbow Emulation

Double Rainbow emulates the M4 optimized implementation of the Rainbow Signature scheme proposed by the authors of [1] in the identically named emulation framework Rainbow, which itself is based on Unicorn. 

- [Primitives](#primitives)
  * [Keypair](#keypair)
  * [Sign](#sign)
  * [Verify](#verify)
- [Collecting Traces](#Collecting-Traces)

## Primitives
### Keypair
Since the generation of the public and secret key is very time consuming when done within the simulation (around 2 hours), it is instead implemented to run on the host system, using the original submission implementation [2].
To generate the keys, run
```shell script
python src/keypair.py
```
This builds the binaries from the original submission package (if not already built), generates the keys and stores them under *rainbow-submission-round2/Reference_Implementation* as *pk_file* and *sk_file*.

### Sign
The signing algorithm runs entirely within the rainbow simulation. The keys are transferred to the emulation and mapped to memory, then the **crypto_sign** function is called. Using cmd line arguments, one can specify the message to sign and where to store the result. Currently, the maximum number of bytes of the message is set to 32. To modify this value, the memory mapping specified in *src/drainbow.py* can be adapted.
To sign a message, run:
```shell script
python src/sign.py -m [path_to_message] -sm [path_to_signed_message]
```
To inject a skipping fault at *skip_address* , run:
```shell script
python src/sign.py -m [path_to_message] -sm [path_to_signed_message] -s --skip_address [skip_address]
```
If *skip_address* is not specified, the fault will be injected at 0x0df96, skipping the sampling of the vinegar variables. The vinegar variables of the prior call to **crypto_sign** will then be reused, allowing the attack described in [3] as "Reuse fault model".

### Verify
The verification is run within the simulation, calling the function **crypto_sign_open**. To verify a message, run:
```shell script
python src/verify.py -m [path_to_message] -sm [path_to_signed_message]
```
Since for rainbow the signature is simply appended to the message, the M4 implementation discards the unsigned message and only checks if the signature part of the signed message is coherent with the message part.

## Collecting Traces
### Attack 1
When collecting signature traces to launch the attack in [3], first **crypto_sign** is run without any faults to generate valid vinegars. These are then stored in *files*. Afterwards, several processes are started in parallel, each first retrieving the vinegars from the prior executed correct signing procedure and afterwards calling **crypto_sign** while injecting the fault at 0x0df96. Since the sampling of the vinegar variables is skipped they reuse the ones generated during the initial call. Each process generates its own random message and stores the result in *m_sm*. 
To collect traces, run:
```shell script
python src/attack1.py -n [n_signatures]
```
The collected traces are stored in the table *profile_records* of the *drainbow* database. Additionally, a row-vector matrix is generated and stored in *m_sm/signature_matrix*. Logs can be stored in the *logs* table. The database server settings can be adjusted in *files/config/ini*. To increase verbosity to info or log, add *-v* or *-vv* respectively.

### Attack 2
For this novel attack, the application of **S** to **y** is skipped when generating signatures. When these faulty signatures are then verified, key-dependent information is extracted from the variables *correct* and *digest_ck*. If the fault is successfully injected, these byte arrays differ and verification fails, while for failed fault-injection, they will remain identical and verification succeeds. This gives us an easy mechanism to verify successful fault injection.
For this attack, run:
```shell script
python src/attack1.py -s --skip_address  0x0e052 -n [n_signatures]  &&
python src/attack2.py -n [n_signatures]
```
The collected traces are stored in the table *profile_records* of the *drainbow* database. Additionally, a row-vector matrix of the signatures is generated and stored in *m_sm/signature_matrix* and a row-vector matrix of the *correct* and *digest_ck* variable pairs is generated and stored in *m_sm/verification_matrix*. As before, logs can be stored in the *logs* table. The database server settings can be adjusted in *files/config.ini*. To increase verbosity to info or log, add *-v* or *-vv* respectively.

[1] Chou, T., Kannwischer, M. J., & Yang, B.-Y. (2021). Rainbow on Cortex-M4. IACR Transactions on Cryptographic Hardware and Embedded Systems, 2021(4), 650–675. https://doi.org/10.46586/tches.v2021.i4.650-675

[2] https://github.com/fast-crypto-lab/rainbow-submission-round2

[3] K. -A. Shim and N. Koo, "Algebraic Fault Analysis of UOV and Rainbow With the Leakage of Random Vinegar Values," in IEEE Transactions on Information Forensics and Security, vol. 15, pp. 2429-2439, 2020, doi: 10.1109/TIFS.2020.2969555.

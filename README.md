# gpg-openssl-encrypt-twice-symmetrically

**TLDR; dual/double/cascaded/chained symmetric encryption based on either GPG or OpenSSL**


The [gpg-openssl-encrypt-twice-symmetrically](https://github.com/8go/gpg-openssl-encrypt-twice-symmetrically)
repository contains a set of `bash` scripts that allow you to encrypt data
(such as a file) _twice_
with two different ciphers in a _symmetric_ way, i.e. with _two_ passwords.
The goal was to provide a set of small scripts that are a good solution
to perform symmetric encryption twice with a result that is safe, secure, and
viable for a long time (10+ years). Encrypting something twice symmetrically is
also known under the terms of _dual, double, cascaded, multiple, or
chained symmetric encryption_.

Two pairs of scripts are provided:

-   a GPG variant: a pair of scripts based on `gpg`
-   an OpenSSL variant: a pair of scripts based on `openssl`
-   each variant has 2 scripts: one to encrypt and one to decrypt
    -   Even though there are 2 scripts, the `encrypt` script has
        the logic for both, encryption and decryption so that all the logic
        is in a single file. This is done for simplicity. The `decrypt`
        script is just a dummy calling the `encrypt` script with an argument.

# Differences between the `GPG` and `OpenSLL` variants

-   different ciphers: Chacha20 vs TwoFish
    -   gpg variant uses first AES256 and then TwoFish
    -   openssl variant uses first Chacha20 and then AES256
-   different amount of iterations of password hashing
    -   higher in openssl variant --> slows attacker down
-   number of iterations of password hashing recall
    -   gpg variant stores it in encrypted file, so not needed on decryption
    -   with openssl variant you need to know/remember this number in order to decrypt!
        This number is hardcoded in the script.
-   resulting file sizes
    -   gpg variant output file sizes are slightly larger
    -   for a plaintext of 347 bytes, openssl variant produced an output of 520 bytes,
        gpg variant an output of 752 bytes

# Similarities between the `GPG` and `OpenSLL` variants

-   both use symmetric encryption
-   both use symmetric encryption twice
-   both use AES256 as one of the ciphers they use
-   both use a digest

# Warning

-   Remember: both variants are ONLY secure if the two passwords are difficult,
    -   using easy password will lead to easy-to-break results
-   It is recommended that you also keep a copy of the scripts that you used
    together with your encrypted files.

* * *
* * *
* * *

# Comments on Symmetric Encryption, State-of-the-art in 2020

## Research from fall 2020

Primary objective of this research was to find a good solution to
dual/double/cascade/multiple/chained symmetric encryption that is safe,
secure, and viable for a long time (10 years).

## Goals

-   symmetric: for ease
-   dual: to not depend on one cipher/algorithm
-   the two ciphers should be as orthogonal, as different, as possible
-   simplicity
-   should use existing, established, respected high level tools
-   should **not** use a library to avoid coding, and in turn to avoid making mistakes
-   quantum resistance

## Preliminary Conclusions

-   Option A:
    openssl with ChaCha20 first, AES-256-CBC second, with message digest
    -   with salt, and password hashing of 100,000,000 rounds, etc.
    -   implementation of openssl solution written in Bash, 400 LOC
    -   example file sizes:
        ```
           520 bytes ::  plaintext-openssl.enc --> output
           471 bytes ::  plaintext-openssl.inf --> meta data
           347 bytes ::  plaintext-openssl     --> input, sentence with 51 words
          3224 bytes ::  plaintext-openssl.png --> QR code with 970x970 pixels
           152 bytes ::  plaintext-openssl.sha --> hash
        241562 bytes ::  plaintext-openssl.svg --> QR code with 970x970 pixels
        ```
-   Option B:
    gpg with AES-256 first, TwoFish second, with message digest
    -   with salt, and password hashing of 65,000,000 rounds, etc.
    -   implementation of openssl solution written in Bash, 400 LOC
    -   example file sizes:
        ```
           752 bytes ::  plaintext-gpg.enc --> output
          2125 bytes ::  plaintext-gpg.inf --> meta data
           347 bytes ::  plaintext-gpg     --> input, sentence with 51 words
          4354 bytes ::  plaintext-gpg.png --> QR code with 1130x1130 pixels
           144 bytes ::  plaintext-gpg.sha --> hash
        335181 bytes ::  plaintext-gpg.svg --> QR code with 1130x1130 pixels
        ```

## Terminology

-   Some use the term `secret key encryption` instead of `symmetric encryption`.
-   Some use the term `public key encryption` instead of `asymmetric encryption`.
-   These terms are used for encrypting twice: dual, double, cascaded, multiple,
      or chained symmetric encryption\_

## Existing implementations

-   gpg2
-   openssl
-   libressl
-   age <https://github.com/FiloSottile/age>
-   rage <https://github.com/str4d/rage>
-   <https://github.com/SixArm/gpg-encrypt>
-   <https://github.com/SixArm/gpg-decrypt>
-   <https://github.com/SixArm/openssl-encrypt>
-   <https://github.com/SixArm/openssl-decrypt>
-   <https://github.com/vsencrypt/vsencrypt>
    -   does double-symmetric-encryption out-of-the-box
    -   No lib imported, no dependency, some 100 lines of C code.
    -   But not widely used.
-   scrypt
-   libsecp256k1 (lib only)
-   libsodium, NaCl, <https://nacl.cr.yp.to> (lib only)

## Interesting reading

-   <https://news.ycombinator.com/item?id=13382734> : good parameters to use with gpg2! must read!
-   <https://stackoverflow.com/questions/28247821/openssl-vs-gpg-for-encrypting-off-site-backups> : openssl vs. gpg

## AES256

-   industry std.
-   <https://crypto.stackexchange.com/questions/6712/is-aes-256-a-post-quantum-secure-cipher-or-not#7869>
    -   Looks like it is save medium term (30 years?)
-   <https://qvault.io/2020/09/10/is-aes-256-quantum-resistant/> called quantum secure IF password is LONG/GOOD
-   <https://security.stackexchange.com/questions/103538/is-it-true-that-aes-128-and-aes-256-are-quantum-resistant>
    -   Looks like quantum resistance is good.
-   First impressions is: AES256-GCM + ChaCha20-Poly1305
    -   Why? One is block cipher, other is stream cipher. --> Orthogonal.
    -   Read: <https://en.wikipedia.org/wiki/Symmetric-key_algorithm>
-   Many AES digest versions in openssl: aes cfb versus cbc cfb1 cfb8 ctr ecb ofb
    -   <https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb#22958889>
    -   <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation> --> Electronic_Codebook (ECB)
    -   use CBC, since none have authentication, add authentication with message-digest or similar

## AES512

-   AES512 does not really exist. It is not defined. And new definition seems to have problems.
    -   <https://crypto.stackexchange.com/questions/20253/why-we-cant-implement-aes-512-key-size/20258#20258>
-   <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard> has key sizes listed as up to 256, AES512 does not exist
-   no aes512 implementation exists
-   not available, neither GPG nor OpenSSL have AES512.
-   unproven, unavailable --> discarded

## Chacha20

-   <https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant>
    -   used by Google, Cloudflare and WireGuard, TLS on mobile
    -   used by Google (on all Android devices)
-   <https://soatok.blog/2020/07/12/comparison-of-symmetric-encryption-methods/>
    -   both have A rating
-   <https://medium.com/asecuritysite-when-bob-met-alice/aes-is-great-but-we-need-a-fall-back-meet-chacha-and-poly1305-76ee0ee61895>
-   ChaCha20 seen as alternative if flaw is detected in AES
-   the order of encryption should be with weaker first (ChaCha20) and with stronger second (AES) :: secret -> ChaCha20 -> AES ==> QR code
-   <https://blog.cloudflare.com/it-takes-two-to-chacha-poly/>
-   <https://cryptobook.nakov.com/quantum-safe-cryptography> --> Chacha20 is supposed to be as quantum safe as AES.
-   <https://github.com/FiloSottile/age> --> `age`
    -   ChaCha20 + Poly1305, ideal
    -   symmetric + asymmetric
    -   modern
    -   Rust implementation as alternative: `rage` <https://github.com/str4d/rage>

## Twofish

-   Twofish looks very solid, well tested and with no known attacks since inception in 1998
-   <https://uwnthesis.wordpress.com/2013/11/11/non-nist-cipher-suite-silent-circle-should-we-abandon-aes-encryption/>
-   <https://silentcircle.wordpress.com/2013/09/30/nncs/>
    -   "Not the NSA”, SilentCircle abandons AES, We are going to replace our use of the AES cipher with the Twofish cipher, as it is a drop-in replacement.
-   Here are quotes from Cryptography Engineering: Design Principles and Practical Applications (Niels Ferguson, Bruce Schneier, Tadayoshi Kohno) :
    -   Twofish ... can be seen as a compromise between AES and Serpent. It is nearly as fast as AES, but it has a larger security margin. Which seems to imply that AES is indeed weaker than Twofish and Serpent.
-   <https://cloudstorageinfo.org/twofish-vs-aes-encryption>
    -   "Twofish vs AES Conclusion": For most applications, the AES algorithm is probably the best option as it is fast and secure enough.
        But if you have a highly confidential piece of information you want to secure and performance isn’t a problem, go for the Twofish algorithm."

## Serpent

-   <https://crypto.stackexchange.com/questions/52978/double-encryption-using-the-same-cipher>
    -   This page is suggesting "serpent" as orthogonal/different from AES.
-   Could not find Serpent implementation, neither GPG nor OpenSSL suport it.
-   Here are quotes from Cryptography Engineering: Design Principles and Practical Applications (Niels Ferguson, Bruce Schneier, Tadayoshi Kohno) :
    -   Serpent ... is built like a tank. Easily the most conservative of all the AES submissions, Serpent is in many ways the opposite of AES.
        Whereas AES puts emphasis on elegance and efficiency, Serpent is designed for security all the way.
-   <https://askubuntu.com/questions/344866/how-can-i-encrypt-a-file-with-the-serpent-encryption-algorithm>
    -   "if you are really concerned about the security of your computer's files and directories then you should try encrypting with triple encryption algorithm AES-Twofish-Serpent. "

## GPG2

-   GPG with TwoFish and AES256 and SHA512 digest (AES first, TwoFish second)
    -   Just 1 app (gpg), long term viable, will be around in 10 years
    -   orthogonal, with authentication built in (no external hash file needed)
    -   See: <https://news.ycombinator.com/item?id=13382734>
    -   Also read this: <https://github.com/SixArm/gpg-encrypt>
-   Options, arguments:
    ```
       gpg --symmetric \
       --cipher-algo aes256 \
       --digest-algo sha256 \
       --cert-digest-algo sha256 \
       --compress-algo none -z 0 \
       --quiet --no-greeting \
       --no-use-agent "$@" \
       --s2k-mode 3 \
       --s2k-digest-algo sha512 \
       --s2k-count 1000000
    ```

## LibreSSL

-   LibreSSL does support AES256-GCM.
-   <https://crypto.stackexchange.com/questions/76177/how-to-encrypt-files-using-aes256-gcm-cipher-under-linux>
-   Not available as package for Ubuntu nor Fedora, would have to be compiled on Linux
-   OpenSSL based on `libressl` is NOT compatible with OpenSSL based on `openssl` lib.
    -   They use different arguments.
    -   Their version numbers are very different: `openssl` is something like v1.1.1g, `libressl` is 2.1.3+.

## Age

-   `age` does not seem widely used, not established? More like an up-and-coming tool. Will age be around in 10 years?
-   no options on purpose to keep it simple, so no fine-tuning possible
-   to be determined: does `age` use library libsodium or NaCl (<https://en.wikipedia.org/wiki/NaCl_(software)>)? The definite answer is to look at their source code and see what libs they import.
-   libsodium / NaCl offers BOTH: AES and ChaCha20 (as well as authentication, i.e. the Poly1305 part), <https://nacl.cr.yp.to>
-   Rust implementation `rage`

## Keybase.io, VeraCrypt

-   VeraCrypt: only does hard-disk encryption (like LUKS), not file encryption
-   keybase.io: They ONLY use asymmetric encryption. No symmetric encryption available. It uses libsodium, or NaCl.

## Misc Thoughts

-   using a random number for iterations could be even more secure but what if you lose the meta data (the .inf file)?
-   using QR code for obfuscation
-   If one ever wants to program encryption stuff, these are 2 good high-level packages:
    -   <https://cryptography.io/en/latest/fernet/>
    -   <https://pynacl.readthedocs.io/en/stable/secret/>

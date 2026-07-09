# Dependencies

## crc32fast

Needed by the full transport mode.

## getrandom

Needed to generate secure values, such as nonces, during the generation of an Authorization Key.

## grammers-crypto

Mainly used to encrypt and decrypt messages exchanged with Telegram's servers, but also contains
other miscellaneous functions such as integer factorization.

## grammers-tl-types

Used to serialize and deserialize the messages exchanged with Telegram's servers.

## flate2

Messages may be gzip-encoded to reduce bandwidth, so this crate is used for both decompressing
incoming messages and compressing them when it is worth it (based on some simple heuristics).

## num-bigint

Used during the generation of the Authorization Key.

## sha1

Used during the generation of the Authorization Key.

## sha2

Used for SHA-256 in the FakeTLS handshake (ClientHello/ServerHello HMAC digest) and for deriving
the AES-CTR keys in the MTProxy obfuscated transport.

## hmac

Used for HMAC-SHA256 in the FakeTLS handshake (computing the ClientHello random digest, verifying
the ServerHello, and deriving the obfuscated transport keys).

## aes

Optional (`mtproxy` feature). Provides the AES-256 block cipher used in the FakeTLS / MTProxy
obfuscated transport (AES-256-CTR stream cipher).

## ctr

Optional (`mtproxy` feature). Provides the CTR mode of operation wrapping `aes` to form the
AES-256-CTR stream cipher used by the MTProxy obfuscated transport.

## subtle

Optional (`mtproxy` feature). Used for constant-time comparison when verifying the FakeTLS
ServerHello HMAC digest.

## rand

Used to generate random bytes for the FakeTLS handshake frame and the ClientHello session/key data.

## hex

Used to decode hex-encoded MTProxy secrets (the key and the embedded cloak domain).

## base64

Used as a fallback to decode base64-encoded MTProxy secrets.

## x25519-dalek

Optional (`mtproxy` feature). Used to generate the X25519 key share embedded in the FakeTLS
ClientHello (matches the TLS 1.3 key_share extension that MTG expects).

## tokio

Provides async I/O primitives (`AsyncRead`/`AsyncWrite`, `io::split`) used by the FakeTLS stream
and framing wrappers.

## bytes

Used for the input and output buffers.

## toml

Used to test that this file lists all dependencies from `Cargo.toml`.

## log

Used to help debug what's going on at the MTP level (such as when future salts are asked for).

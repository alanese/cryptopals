# What is this?
Solutions to the Cryptopals challenges (https://cryptopals.com/) written in Go, as I get through them.

# What's where?
1. `HexToB64` in `byte_utils.go`
2. `XorBufs` in `crypto_utils.go`
3. Included in (5) - use a slice of length 1
4. Use (3) to decrypt each with all possible keys, scoring each result with `ScoreText` in `crypto_utils.go`. Best score is most likely the encrypted text. A sample corpus is required; I used the text of Cryptonomicon.
5. `XorEncrypt` in `encrypt_decrypt.go`
6. `BreakRepeatedXor` in `encrypt_decrypt.go`. Sample corpus required.
7. `DecryptAESECB` in `encrypt_decrypt.go`
8. `DetectAESECB` in `crypto_utils.go`. Whether it can successfully detect ECB depends heavily on the plaintext.
9. `PKCSPad` in `crypto_utils.go` - also works on input that is more than one block long
10. `DecryptAESCBC` in `crypto_utils.go` - No longer uses my own implementation of CBC; once I had it working I replaced it with Go's included implementation.
11. Use `GenerateRandomByteSlice` in `byte_utils.go` to generate the random key and padding; use (8) to detect.
12. `MysteryEncrypt` in `set_2_utils.go` to encrypt (using a randomly-generated key); `BreakMysteryEncrypt` in `set_2_utils.go` to break.
13. `CreateEncryptedAdminProfile` in `set_2_utils.go`
14. Currently in `main.go`; to be moved later.
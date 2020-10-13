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
14. `MysteryEncryptHard` in `set_2_utils.go` to encrypt (pass a randomly-generated key and padding); `BreakMysteryEncryptHard` in `set_2_utils.go` to break.
15. `StripPKCS7Padding` in `crypto_utils.go`
16. Create profile with `Challenge16Func` in `set_2_utils.go`, check for admin status with `Challenge16AdminCheck` in `set_2_utils.go`. Creating the fake encrypted admin profile in `Challenge16ForgeData` in `set_2_utils.go`.
17. Choose and encrypt a plaintext using `Challenge17Encrypt` in `set_3_utils.go`. Decrypt and return an error wiith `Challenge17Decrypt` in `set_3_utils.go`. Break individual blocks using `Challenge17GetLastBlock` in `set_3_utils.go` on the appropriate prefix of the ciphertext. This attack cannot decrypt the first block without manipulating (or at least knowing) the IV.
18. `Challenge18Decrypt` in `set_3_utils.go`.
19. Not in code
20. `Challenge20` in `set_3_utils.go`. Didn't decode perfectly with my chosen sample corpus, but enough for me to figure out what the plaintext was; perhaps a different sample would have worked a bit better.
21. The `Twister` type in `twister.go`. Create a new one with `NewTwister`, get the next value with `Next`.
22. `Challenge22RandomNum` in `set_3_utils.go` to create the twister and get the first value, `Challenge22BreakSeed` in `set_3_utils.go` to find the seed.
23. `CloneTwister` in `set_3_utils.go`
24. Encrypt/decrypt with `EncryptMT19937Stream` in `encrypt_decrypt.go`. Remainder of the challenge in `C24RecoverKey`, `C24GenerateResetToken`, and `C24ValidateToken` in `set_3_utils.go`
25. Edit function at `C25Edit` in `set_4.go`, break using `C25BreakEdit` in `set_4.go`.
26. Create profile with `Challenge26Func` in `set_4.go`, check for admin status with `Challenge26AdminCheck` in `set_4.go`. Create the fake admin profile with `Challenge26ForgeData` in `set_4.go`. This is almost entirely copy/pasted from challenge 16; the only required modifications are changing the encryption/decryption function used and changing some indices in `Challenge26ForgeData` to alter a different block.
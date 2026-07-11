package padding_oracle

// This file is pure byte manipulation — no I/O — so the mutation logic is unit-
// testable in isolation.
//
// In CBC, the last plaintext block is P[n-1] = D(C[n-1]) XOR C[n-2]. Flipping a
// byte of the penultimate ciphertext block C[n-2] therefore flips the byte at the
// same offset of P[n-1] — the block whose PKCS#7 padding the target validates.
// Flipping the LAST byte of C[n-2] corrupts the final (padding-length) byte of
// P[n-1], the canonical padding-oracle probe.

// FlipPenultimateLastByte returns a copy of dec with the low bit of the last byte
// of the penultimate block (block index n-2) flipped. This changes the last
// (padding) byte of the final plaintext block.
func FlipPenultimateLastByte(dec []byte, blockSize int) []byte {
	return FlipPenultimateByteAt(dec, blockSize, 1)
}

// FlipPenultimateByteAt returns a copy of dec with the low bit of a byte inside
// the penultimate block flipped. byteOffsetFromBlockEnd counts back from the end
// of that block: 1 is the last byte, 2 the second-to-last, and so on. Using a
// different offset probes a different plaintext position, so a second confirmation
// round exercises a distinct bit position from the first.
//
// It never panics: if dec is too short to hold two whole blocks, or the offset is
// out of range, the input is returned unchanged (a copy).
func FlipPenultimateByteAt(dec []byte, blockSize, byteOffsetFromBlockEnd int) []byte {
	out := make([]byte, len(dec))
	copy(out, dec)
	if blockSize <= 0 || len(out) < 2*blockSize {
		return out
	}
	if byteOffsetFromBlockEnd < 1 {
		byteOffsetFromBlockEnd = 1
	}
	if byteOffsetFromBlockEnd > blockSize {
		byteOffsetFromBlockEnd = blockSize
	}
	// The penultimate block ends at len-blockSize; its last byte is len-blockSize-1.
	idx := len(out) - blockSize - byteOffsetFromBlockEnd
	out[idx] ^= 0x01
	return out
}

// MalformedControl corrupts the ENCODING of an already-encoded ciphertext so the
// target fails to decode it BEFORE any block decryption runs — yielding a
// decode/pre-decrypt error class distinct from a padding error. Appending
// characters outside every base64/hex alphabet guarantees the decode step fails
// regardless of which encoding was used.
func MalformedControl(encoded string) string {
	return encoded + "!!"
}

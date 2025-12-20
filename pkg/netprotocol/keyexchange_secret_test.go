package netprotocol_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"net"
	"testing"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
)

func TestKeyExchange_SharedSecretAligned_NoRatchet(t *testing.T) {
	alicePriv, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %s", err.Error())
	}
	bobPriv, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %s", err.Error())
	}

	alicePub := alicePriv.Public()
	bobPub := bobPriv.Public()

	aliceAddr, err := alicePub.Address()
	if err != nil {
		t.Fatalf("alice address: %s", err.Error())
	}
	bobAddr, err := bobPub.Address()
	if err != nil {
		t.Fatalf("bob address: %s", err.Error())
	}

	t.Logf("Alice Signing key: %#x", alicePub.SigningKey)
	t.Logf("Bob Signing key:   %#x", bobPub.SigningKey)

	netUpdate := &identity.NetworkUpdate{
		Timestamp:  1,
		NetAddress: net.IPv6loopback, // ::1
	}
	signedNetUpdate, err := netUpdate.Sign(alicePriv.SigningPrivateKey)
	if err != nil {
		t.Fatalf("sign network update: %s", err.Error())
	}

	signedKeyBundle, err := alicePub.Sign(alicePriv.SigningPrivateKey)
	if err != nil {
		t.Fatalf("sign key bundle: %s", err.Error())
	}

	aliceEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("alice ephemeral: %s", err.Error())
	}

	req := &netprotocol.KeyExchangeRequest{
		SendIDAddr:          aliceAddr,
		RecvIDAddr:          bobAddr,
		SignedKeyBundle:     signedKeyBundle,
		SignedNetworkUpdate: signedNetUpdate,
		EphemeralKey:        aliceEphemeral.PublicKey(),
	}

	sigReq, err := req.Sign(alicePriv.SigningPrivateKey)
	if err != nil {
		t.Fatalf("sign request: %s", err.Error())
	}

	rawReq, err := sigReq.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal signed request: %s", err.Error())
	}

	// Bob receives request: and now parses + verifies it
	gotSigReq := &netprotocol.SignedKeyExchangeRequest{}
	if err := gotSigReq.UnmarshalBinary(rawReq); err != nil {
		t.Fatalf("unmarshal signed request: %s", err.Error())
	}

	gotReq := gotSigReq.Inner
	if gotReq == nil {
		t.Fatalf("nil inner request")
	}

	// verify the key bundle
	if err := gotReq.SignedKeyBundle.Verify(); err != nil {
		t.Fatalf("verify signed key bundle: %s", err.Error())
	}
	if err := gotReq.SignedNetworkUpdate.Verify(alicePub.SigningKey); err != nil {
		t.Fatalf("verify signed network update: %s", err.Error())
	}
	if err := gotSigReq.Verify(alicePub.SigningKey); err != nil {
		t.Fatalf("verify signed request: %s", err.Error())
	}

	//
	bobEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("bob ephemeral: %s", err.Error())
	}

	staticSecretBob, err := bobPriv.DiffieHellmanPrivateKey.ECDH(alicePub.DiffieHellmanKey)
	if err != nil {
		t.Fatalf("bob static ECDH: %s", err.Error())
	}

	ephemeralSecretBob, err := bobEphemeral.ECDH(gotReq.EphemeralKey)
	if err != nil {
		t.Fatalf("bob ephemeral ECDH: %s", err.Error())
	}

	secretsBob := make([]byte, 0, len(staticSecretBob)+len(ephemeralSecretBob))
	secretsBob = append(secretsBob, staticSecretBob...)
	secretsBob = append(secretsBob, ephemeralSecretBob...)
	sharedBob := sha3.Sum256(secretsBob)

	// A dummy ratchet key for Bob to include in his response
	dummyRatchetPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dummy ratchet key: %s", err.Error())
	}

	resp := &netprotocol.KeyExchangeResponse{
		SendIDAddr:   bobAddr,
		RecvIDAddr:   aliceAddr,
		EphemeralKey: bobEphemeral.PublicKey(),
		RatchetKey:   dummyRatchetPriv.PublicKey(),
	}

	// Bob signs his response
	sigResp, err := resp.Sign(bobPriv.SigningPrivateKey)
	if err != nil {
		t.Fatalf("sign response: %s", err.Error())
	}

	// Bob serializes his signed response
	rawResp, err := sigResp.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal signed response: %s", err.Error())
	}

	// Alice receives response: verifies it and parses it
	gotSigResp := &netprotocol.SignedKeyExchangeResponse{}
	if err := gotSigResp.UnmarshalBinary(rawResp); err != nil {
		t.Fatalf("unmarshal signed response: %s", err.Error())
	}

	// Alice verifies Bob's signature
	if err := gotSigResp.Verify(bobPub.SigningKey); err != nil {
		t.Fatalf("verify signed response: %s", err.Error())
	}

	// Extract inner response
	gotResp := gotSigResp.Inner
	if gotResp == nil {
		t.Fatalf("nil inner response")
	}

	// Now Alice computes the shared secret : NOTE: no keybundle management here: 'NO DB'
	staticSecretAlice, err := alicePriv.DiffieHellmanPrivateKey.ECDH(bobPub.DiffieHellmanKey)
	if err != nil {
		t.Fatalf("alice static ECDH: %s", err.Error())
	}

	ephemeralSecretAlice, err := aliceEphemeral.ECDH(gotResp.EphemeralKey)
	if err != nil {
		t.Fatalf("alice ephemeral ECDH: %s", err.Error())
	}

	secretsAlice := make([]byte, 0, len(staticSecretAlice)+len(ephemeralSecretAlice))
	secretsAlice = append(secretsAlice, staticSecretAlice...)
	secretsAlice = append(secretsAlice, ephemeralSecretAlice...)
	sharedAlice := sha3.Sum256(secretsAlice)

	// Compare shared secrets
	if !bytes.Equal(sharedAlice[:], sharedBob[:]) {
		t.Fatalf("shared secrets differ")

	}
	// print them ontop of each other for visual inspection
	t.Logf("Shared Secret: %#x", sharedAlice)
	t.Logf("Shared Secret: %#x", sharedBob)
}

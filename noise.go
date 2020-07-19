// Copyright 2020 Matt Montgomery
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"fmt"
	"errors"
	"strings"
	"log"

    "github.com/flynn/noise"
)

var noiseConfig noise.Config
var initialState *noise.HandshakeState
var send, receive *noise.CipherState

func StartNoiseServer(anon bool) {
	if anon {
		log.Printf("Encryption: NONE")
		return
	}

	// uses state to send file data to the client
	initializeNoise(true, "temp-psk")
}

func ReadClientHandshake(message []byte) []byte {
	_, _, _, err := initialState.ReadMessage(nil, message)
	if err != nil {
		log.Printf("Unable to read handshake from client: %s", err)
		return nil
	}

	postWrite, to, from, writeErr := initialState.WriteMessage(nil, nil)
	if writeErr != nil {
		log.Printf("Unable to reply to handshake from client: %s", writeErr)
		return nil
	}

	log.Printf("Securely connected to client")
	send = to
	receive = from

	return postWrite
}

func StartNoiseClient(psk string) []byte {
	// uses state to receive initial metadata struct and then raw data
	initializeNoise(false, psk)

	// Send initial message
	hello, _, _, err := initialState.WriteMessage(nil, nil)
	if err != nil {
		log.Fatalf("Unable to initiate handshake with server: %s", err)
	}

	return hello
}

func ReadServerHandshake(message []byte) {
	_, to, from, writeErr := initialState.ReadMessage(nil, message)
	if writeErr != nil {
		log.Fatalf("Unable to reply to handshake from server: %s", writeErr)
		return
	}

	log.Printf("Securely connected to server")
	send = to
	receive = from
}

func initializeNoise(isServer bool, rawPsk string) {
	/*
		PSKs will use the numbers 1-99 (inclusive) and all 7,776 diceware words.
		This provides 98 * 7776 * 7776 = 5,925,685,248 (roughly 2^32) possible PSKs.
	*/

	if isServer && rawPsk == "" {
		// TODO: randomize in the form ##-diceware-diceware
		rawRandom := make([]byte, 3)
		rand.Read(rawRandom)
		rawPsk = fmt.Sprintf("%x", rawRandom)
	}
	
	transform := strings.ReplaceAll(rawPsk, "-", "")
	hash := noise.HashBLAKE2s.Hash()
	hash.Write([]byte(transform))
	psk := hash.Sum(nil)

	// Since handshake NN uses ephemeral keys on both sides, confidentiality is ensured with the PSK
	noiseConfig = noise.Config {
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern: noise.HandshakeNN,
		Initiator: !isServer,
		PresharedKey: psk,
		PresharedKeyPlacement: 0,
	}

	log.Printf("Encryption: %s", noiseConfig.CipherSuite.Name())
	if isServer {
		log.Printf("==========================================")
		log.Printf("Transfer password: %s", rawPsk)
		log.Printf("==========================================")
	}

	stateErr := errors.New("ok")
	initialState, stateErr = noise.NewHandshakeState(noiseConfig)
	if stateErr != nil {
		log.Fatalf("Unable to setup initial handshake state: %s", stateErr)
	}
}

func Encrypt(data []byte) []byte {
	return send.Encrypt(nil, nil, data)
}

func Decrypt(data []byte) []byte {
	decrypted, err := send.Decrypt(nil, nil, data)
	if err != nil {
		log.Fatalf("Failed to decrypt message: %s", err)
		return nil
	}

	return decrypted
}
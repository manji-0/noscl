package main

import (
	"encoding/hex"
	"fmt"
	"log"
  "regexp"

	"github.com/btcsuite/btcd/btcec"
	"github.com/docopt/docopt-go"

	"github.com/fiatjaf/go-nostr/nip06"
)

func setPrivateKey(opts docopt.Opts) {
	keyhex := opts["<key>"].(string)
	keylen := len(keyhex)

	if keylen < 64 {
		log.Printf("key too short was %d characters, must be 32 bytes hex-encoded, i.e. 64 characters.\n", keylen)
		return
	}

	if _, err := hex.DecodeString(keyhex); err != nil {
		log.Printf("Error decoding key from hex: %s\n", err.Error())
		return
	}

	config.PrivateKey = keyhex
}

func showPublicKey(opts docopt.Opts) {
	if config.PrivateKey == "" {
		log.Printf("No private key set.\n")
		return
	}

	pubkey := getPubKey(config.PrivateKey)
	if pubkey != "" {
		fmt.Printf("%s\n", pubkey)
	}
}

func getPubKey(privateKey string) string {
	if keyb, err := hex.DecodeString(privateKey); err != nil {
		log.Printf("Error decoding key from hex: %s\n", err.Error())
		return ""
	} else {
		_, pubkey := btcec.PrivKeyFromBytes(btcec.S256(), keyb)
		return hex.EncodeToString(pubkey.X.Bytes())
	}
}

func findKey(opts docopt.Opts) {
  r := regexp.MustCompile(opts["<pattern>"].(string))

  for {
    sec, err := _keyGen()

    if err != nil {
      continue
    }

    pub := getPubKey(sec)

    if r.MatchString(pub) {
      fmt.Println(`{"status": "success", "pubkey": "` + pub + `", "seckey": ` + sec + `"}`)
      break
    } else {
      fmt.Println(`{"status": "failed", "pubkey": "` + pub + `", "seckey": ` + sec + `"}`)
    }
  }
}

func keyGen(opts docopt.Opts) {
  sk, err := _keyGen()

  if err != nil {
    return
  }

	fmt.Println(sk)
}

func _keyGen() (string, error) {
  seedWords, err := nip06.GenerateSeedWords()

  if err != nil {
    return "", err
  }

  seed := nip06.SeedFromWords(seedWords)
  sk, err :=nip06.PrivateKeyFromSeed(seed)

  if err != nil {
    return "", err
  }

  return sk, nil
}

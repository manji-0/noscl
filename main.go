package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/docopt/docopt-go"
	"github.com/mitchellh/go-homedir"
)

const USAGE = `noscl

Usage:
  noscl home
  noscl setprivate <key>
  noscl sign <event-json>
  noscl verify <event-json>
  noscl public
  noscl publish [--kind=<kind>] [--reference=<id>...] [--profile=<id>...] <content>
  noscl message [--reference=<id>...] <id> <content>
  noscl metadata --name=<name> [--about=<about>] [--picture=<picture>]
  noscl profile <key>
  noscl follow <key> [--name=<name>]
  noscl unfollow <key>
  noscl event <id>
  noscl share-contacts
  noscl key-gen
  noscl find-key <pattern>
  noscl relay
  noscl relay add <url>
  noscl relay remove <url>
  noscl relay recommend <url>
`

func main() {
	// find datadir
	flag.StringVar(&config.DataDir, "datadir", "~/.config/nostr",
		"Base directory for configurations and data from Nostr.")
	flag.Parse()
	config.DataDir, _ = homedir.Expand(config.DataDir)
	os.Mkdir(config.DataDir, 0700)

	// logger config
	log.SetPrefix("<> ")

	// parse config
	path := filepath.Join(config.DataDir, "config.json")
	f, err := os.Open(path)
	if err != nil {
		saveConfig(path)
		f, _ = os.Open(path)
	}
	f, _ = os.Open(path)
	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		log.Fatal("can't parse config file " + path + ": " + err.Error())
		return
	}
	config.Init()

	// parse args
	opts, err := docopt.ParseDoc(USAGE)
	if err != nil {
		return
	}

	switch {
	case opts["home"].(bool):
		home(opts)
	case opts["setprivate"].(bool):
		// TODO make this read STDIN and encrypt the key locally
		setPrivateKey(opts)
		saveConfig(path)
	case opts["sign"].(bool):
		signEventJSON(opts)
	case opts["verify"].(bool):
		verifyEventJSON(opts)
	case opts["public"].(bool):
		showPublicKey(opts)
	case opts["publish"].(bool):
		publish(opts)
	case opts["message"].(bool):
		message(opts)
	case opts["share-contacts"].(bool):
		shareContacts(opts)
	case opts["key-gen"].(bool):
		keyGen(opts)
  case opts["find-key"].(bool):
    findKey(opts)
	case opts["metadata"].(bool):
		setMetadata(opts)
	case opts["profile"].(bool):
		showProfile(opts)
	case opts["follow"].(bool):
		follow(opts)
		saveConfig(path)
	case opts["unfollow"].(bool):
		unfollow(opts)
		saveConfig(path)
	case opts["event"].(bool):
		view(opts)
	case opts["relay"].(bool):
		switch {
		case opts["add"].(bool):
			addRelay(opts)
			saveConfig(path)
		case opts["remove"].(bool):
			removeRelay(opts)
			saveConfig(path)
		case opts["recommend"].(bool):
			recommendRelay(opts)
		default:
			listRelays(opts)
		}
	}
}

package main

import (
	"encoding/json"
	"log"
)

type Metadata struct {
	Filename string
	Size     int64
}

func Encode(raw interface{}) []byte {
	encoded, err := json.Marshal(raw)

	if err != nil {
		log.Fatalf("Unable to marshal %#v to JSON: %s", raw, err)
	}

	return encoded
}
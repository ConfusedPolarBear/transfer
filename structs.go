package main

import (
	"encoding/json"
	"log"
)

type Metadata struct {
	Filename string
	Size     int64
}

type Chunk struct {
	Data   []byte
}

func Encode(raw interface{}) []byte {
	encoded, err := json.Marshal(raw)
	if err != nil {
		log.Fatalf("Unable to marshal %#v to JSON: %s", raw, err)
	}

	return encoded
}

func Decode(data []byte, v interface{}) {
	err := json.Unmarshal(data, v)
	if err != nil {
		log.Fatalf("Unable to unmarshal %#v: %s", data, err)
	}
}
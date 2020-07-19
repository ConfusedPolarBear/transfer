// Copyright 2020 Matt Montgomery
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/base32"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/cheggaaa/pb"
)

/* Features to implement:
	Random PSKs
	SHA256 checksum - hash client side and if it doesn't match, delete the file
	Post download, send an encrypted command to the server which tells it to reset the encryption state
	Implement a max number of downloads (defaults to unlimited)
*/

var filename string
var file *os.File
var size int64

func main() {
	anonymousFlag := flag.Bool("a", false, "Enable anonymous downloads through a web browser. Disables transport encryption!")
	portFlag := flag.String("l", "1832", "Listen port for server")
	clientFlag := flag.String("c", "", "Connect to the provided server")
	filenameFlag := flag.String("f", "", "File to send")
	pskFlag := flag.String("p", "", "Password to connect to server with")

	flag.Parse()
	anonymous := *anonymousFlag
	port := *portFlag
	client := *clientFlag
	filename = *filenameFlag
	server := (filename != "")
	psk := *pskFlag

	if !server && client == "" {
		log.Fatalf("Must act as a server or specify address to connect to")
	}

	if server {
		// Open and stat input file
		err := errors.New("ok")
		file, err = os.Open(filename)
		if err != nil {
			log.Fatalf("Unable to open file '%s': %s", filename, err)
		}

		stat, _ := file.Stat()
		size = stat.Size()

		// Print local port and addresses
		local := ""
		addresses, _ := net.InterfaceAddrs()
		for _, raw := range addresses {
			// Remove the subnet
			addr := raw.String()
			slash := strings.LastIndex(addr, "/")
			if slash != -1 {
				addr = addr[:slash]
			}

			local += addr + ", "
		}
		log.Printf("Addresses: %s", local)
		log.Printf("Listening on port %s", port)

		log.Printf("Sending file %s (%d bytes)", filename, size)

		// Initialize Noise and start web server
		StartNoiseServer(anonymous)
		StartServer(port, anonymous)

	} else {
		// Verify server address and normalize it if needed
		original := client
		parsed, parseErr := url.Parse(client)
		if parseErr != nil {
			log.Fatalf("Unable to parse server address %s", client)
		}

		if parsed.Scheme == "" {
			parsed.Scheme = "http"
			parsed.Path += ":1832"
		}

		client = parsed.String()

		if client != original {
			log.Printf("Rewrote server address from '%s' to '%s'", original, client)
		}

		// Initialize Noise and get handshake msg
		raw := StartNoiseClient(psk)
		encoded := base32.StdEncoding.EncodeToString(raw)
		handshake := Get(client + "/api/v0/key/" + encoded)
		
		ReadServerHandshake(handshake)

		// Noise is now setup and ready to use, get metadata and sleep
		metaRaw := Decrypt(Get(client + "/api/v0/metadata"))
		var meta Metadata
		Decode(metaRaw, &meta)
		size = meta.Size

		log.Printf("Will download %s (%d bytes) in 3 seconds unless Ctrl-C is pressed...", meta.Filename, size)
		time.Sleep(3 * time.Second)

		log.Printf("Downloading")
		download(client + "/api/v0/download")
	}
}

func Get(url string) []byte {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Unable to connect to server: %s", err)
	}

	length := resp.ContentLength
	if length > 65536 {
		log.Printf("Warning: truncating body to noise maximum, was originally %d", length)
		length = 65536

	} else if length == -1 {
		// We can't handle chunked responses here
		log.Fatalf("Cannot handle chunked responses with Get()")
	}

	var data = make([]byte, length)
	resp.Body.Read(data)

	return data
}

func StartServer(port string, anonymous bool) {
	port = ":" + port

	r := mux.NewRouter()

	// Transfer client support
	r.HandleFunc("/api/v0/key/{handshake}", setupKey).Methods("GET")
	r.HandleFunc("/api/v0/metadata", getMetadata).Methods("GET")
	r.HandleFunc("/api/v0/download", upload).Methods("GET")
	
	// Web browser support
	if anonymous {
		log.Printf("Warning: anonymous access has been enabled")
		r.HandleFunc("/", browserDownload).Methods("GET")
	}

	srv := &http.Server{
		Handler:      r,
		Addr:         port,
		WriteTimeout: 15 * time.Minute,
		ReadTimeout:  15 * time.Second,
	}
	
	log.Fatal(srv.ListenAndServe())
}

func browserDownload(w http.ResponseWriter, r *http.Request) {
	log.Printf("Anonymous user is downloading from %s", r.RemoteAddr)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(filename)))

	// FIXME: this is not thread safe :(
	// use a mutex?
	file.Seek(0, 0)
	_, err := io.Copy(w, file)
	if err != nil {
		log.Printf("Failed to fully transmit file: %s", err)
	}
}

func setupKey(w http.ResponseWriter, r *http.Request) {
	encoded := mux.Vars(r)["handshake"]
	handshake, err := base32.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("Invalid handshake")
		return
	}

	w.Write(ReadClientHandshake(handshake))
}

func getMetadata(w http.ResponseWriter, r *http.Request) {
	packet := Encode(Metadata {
		Filename: filename,
		Size:     size,
	})

	w.Write(Encrypt(packet))
}

func upload(w http.ResponseWriter, r *http.Request) {
	// FIXME: use locking
	file.Seek(0, 0)

	progress := pb.New64(size)
	progress.SetUnits(pb.U_BYTES)
	progress.Start()

	var data = make([]byte, 65536)
	for {
		count, err := file.Read(data)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading file: %s", err)
			}

			break
		}

		if len(data) > count {
			data = data[:count]
		}

		// TODO: wrap this in a JSON struct
		crypted := Encrypt(data)
		w.Write(Encode(Chunk {
			Data: crypted,
		}))

		progress.Add(count)
	}

	progress.Finish()
}

func download(addr string) {
	dest, openErr := os.OpenFile("/tmp/dest", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0655)
	if openErr != nil {
		log.Fatalf("Unable to open destination: %s", openErr)
	}

	// TODO: dedup with Get()
	resp, httpErr := http.Get(addr)
	if httpErr != nil {
		log.Fatalf("Unable to connect to server: %s", httpErr)
	}

	progress := pb.New64(size)
	progress.SetUnits(pb.U_BYTES)
	progress.Start()

	var data = make([]byte, 1*1024*1024)
	err := errors.New("")
	reader := bufio.NewReader(resp.Body)
	for {
		// Read until the end of the next JSON byte stream
		data, err = reader.ReadBytes('}')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading file: %s", err)
			}

			break
		}

		var chunk Chunk
		Decode(data, &chunk)
		decrypted := Decrypt(chunk.Data)
		dest.Write(decrypted)

		progress.Add(len(decrypted))
	}

	progress.Finish()

	log.Printf("Download successful")
}

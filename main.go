// Copyright 2020 Matt Montgomery
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
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
	"syscall"

	"github.com/gorilla/mux"
	"github.com/cheggaaa/pb"
	"golang.org/x/crypto/ssh/terminal"
)

/* Features to implement:
	Upload file/text?
	Multiple file support (tar all files, send and auto extract)
*/

var filename, outputName string
var file *os.File
var size int64
var anonymous bool
var psk string
var max int
var failures = 3
var srv *http.Server

func main() {
	anonymousFlag := flag.Bool("a", false, "Enable anonymous downloads through a web browser. Disables transport encryption!")
	portFlag := flag.String("l", "1832", "Listen port for server")
	clientFlag := flag.String("c", "", "Connect to the provided server")
	filenameFlag := flag.String("f", "", "File to send")
	outputFlag := flag.String("o", "", "Output filename (defaults to original filename)")
	pskFlag := flag.String("p", "", "Password to secure transfer with. If empty, servers will generate one and clients will prompt")
	maxFlag := flag.Int("m", 1, "Maximum number of transfers permitted")

	flag.Parse()
	anonymous = *anonymousFlag
	port := *portFlag
	client := *clientFlag
	filename = *filenameFlag
	outputName = *outputFlag
	server := (filename != "")
	psk = *pskFlag
	max = *maxFlag

	if !server && client == "" {
		log.Fatalf("Must act as a server (-f filename) or specify address to connect to (-c address)")
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

			if addr == "127.0.0.1" || addr == "::1" {
				continue
			}

			local += addr + ", "
		}
		log.Printf("Listening on port %s on: %s", port, local[:len(local)-2])

		log.Printf("Sending file %s (%d bytes)", filename, size)

		// Initialize Noise and start web server
		psk = StartNoiseServer(anonymous, psk)
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

		doPrompt := (psk == "")
		for {
			if doPrompt {
				psk = prompt("Enter password", true)
			}
	
			// Initialize Noise and get handshake msg
			raw := StartNoiseClient(psk)
			encoded := base32.StdEncoding.EncodeToString(raw)
			handshake := Get(client + "/api/v0/key/" + encoded)
			
			if(ReadServerHandshake(handshake)) {
				break
			} else if !doPrompt {
				log.Fatalf("Invalid PSK")
			}
		}

		// Noise is now setup and ready to use, get metadata and sleep
		metaRaw := Decrypt(Get(client + "/api/v0/metadata"), []byte("metadata"))
		var meta Metadata
		Decode(metaRaw, &meta)
		filename = meta.Filename
		size = meta.Size

		log.Printf("Fingerprint: %s", GetChannel())
		log.Printf("Press Enter to confirm transfer of %s (%d bytes)", meta.Filename, size)
		prompt("", false)

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

	srv = &http.Server{
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

	// FIXME: this is not thread safe and will happily serve up truncated files if more than one client makes a request
	// use a mutex?
	file.Seek(0, 0)

	progress := pb.New64(size)
	progress.SetUnits(pb.U_BYTES)
	progress.Start()
	barReader := progress.NewProxyReader(file)
	_, err := io.Copy(w, barReader)
	if err != nil {
		log.Printf("Failed to fully transmit file: %s", err)
	}

	progress.Finish()
}

func setupKey(w http.ResponseWriter, r *http.Request) {
	encoded := mux.Vars(r)["handshake"]
	incoming, err := base32.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("Invalid handshake")
		return
	}

	handshake := ReadClientHandshake(incoming)
	if handshake == nil {
		failures -= 1
		if failures <= 0 {
			log.Printf("Warning: Too many failed authentications, exiting")
			srv.Shutdown(context.TODO())
		} else {
			log.Printf("Warning: Failed to authenticate connecting client, %d more attempts remaining", failures)
		}

		http.Error(w, "", http.StatusForbidden)
		return
	} else {
		w.Write(handshake)
	}

	log.Printf("Fingerprint: %s", GetChannel())
}

func getMetadata(w http.ResponseWriter, r *http.Request) {
	packet := Encode(Metadata {
		Filename: filepath.Base(filename),
		Size:     size,
	})

	w.Write(Encrypt(packet, []byte("metadata")))
}

func upload(w http.ResponseWriter, r *http.Request) {
	// No locking is needed here because of the way we have noise setup - it's state machine only allows one client
	// to connect at a time, new clients fail with the error "noise: no handshake messages left"
	file.Seek(0, 0)

	progress := pb.New64(size)
	progress.SetUnits(pb.U_BYTES)
	progress.Start()

	hasher := sha256.New()

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

		crypted := Encrypt(data, []byte("data"))
		w.Write(Encode(Chunk {
			Data: crypted,
			Type: "data",
		}))

		hasher.Write(data)
		progress.Add(count)
	}

	hash := Encrypt(hasher.Sum(nil), []byte("hash"))
	w.Write(Encode(Chunk {
		Data: hash,
		Type: "hash",
	}))
	progress.Finish()

	log.Printf("Upload complete")

	max -= 1
	if max != 0 {
		log.Printf("%d more transfers permitted, resetting for next client", max)
		ResetEncryptionState()
		StartNoiseServer(anonymous, psk)

	} else {
		log.Printf("Maximum number of transfers reached, exiting")
		srv.Shutdown(context.TODO())
	}
}

func download(addr string) {
	// Check to see if the file is already in the current directory only if we haven't specified a filename manually
	if outputName == "" {
		filename = "./" + filename
		_, openErr := os.Open(filename)
		if openErr == nil {
			original := filename
			filename = fmt.Sprintf("%s.%d", filename, GetNumber(1000))

			log.Printf("Refusing to overwrite %s, downloaded file will be saved as %s", original, filename)
		}
	} else {
		filename = outputName
	}

	dest, openErr := os.OpenFile(filename, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0655)
	if openErr != nil {
		log.Fatalf("Unable to open destination: %s", openErr)
	}

	// TODO: dedup with Get()
	resp, httpErr := http.Get(addr)
	defer resp.Body.Close()
	if httpErr != nil {
		log.Fatalf("Unable to connect to server: %s", httpErr)
	}

	progress := pb.New64(size)
	progress.SetUnits(pb.U_BYTES)
	progress.Start()
	
	hasher := sha256.New()
	valid := false

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
		if chunk.Type == "data" {
			decrypted := Decrypt(chunk.Data, []byte("data"))
			dest.Write(decrypted)
			hasher.Write(decrypted)
			progress.Add(len(decrypted))

		} else if chunk.Type == "hash" {
			hashRecv := Decrypt(chunk.Data, []byte("hash"))
			received := fmt.Sprintf("%x", hashRecv)
			calculated := fmt.Sprintf("%x", hasher.Sum(nil))

			if calculated != received {
				log.Printf("Warning: Received data checksum does not match source")
			} else {
				valid = true
			}

			break
		}
	}

	progress.Finish()

	if valid {
		log.Printf("Download successful, received data checksum matches source")
		dest.Sync()
	}
}

func prompt(msg string, hide bool) string {
	data := ""
	err := errors.New("")

	if msg != "" {
		fmt.Printf("%s: ", msg)
	}

	reader := bufio.NewReader(os.Stdin)

	if hide {
		raw, secretErr := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		err = secretErr
		data = string(raw)

	} else {
		raw, clearErr := reader.ReadString('\n')
		err = clearErr
		data = strings.TrimSpace(raw)		// Remove the trailing newline
	}

	if err != nil {
		log.Fatalf("Unable to prompt for input: %s", err)
	}

	return data
}
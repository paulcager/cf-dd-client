package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	ip, err := publicIP()
	if err != nil {
		log.Fatal(err)
	}

	api, err := cloudflare.New(os.Getenv("CF_API_KEY"), os.Getenv("CF_API_EMAIL"))
	if err != nil {
		log.Fatal(err)
	}

	id, err := api.ZoneIDByName("paulcager.org")
	if err != nil {
		log.Fatal(err)
	}

	zones, err := api.DNSRecords(id, cloudflare.DNSRecord{Type: "A", Name: "home.paulcager.org"})
	if err != nil {
		log.Fatal(err)
	}

	for _, z := range zones {
		if z.Content != ip {
			fmt.Printf("Setting home.paulcager.org A from %s to %s\n", z.Content, ip)
			z.Content = ip
			err := api.UpdateDNSRecord(z.ZoneID, z.ID, z)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello World")
	})

	certManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("certs"),
	}

	server := &http.Server{
		Addr:    ":8443",
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	go http.ListenAndServe(":8080", certManager.HTTPHandler(nil))
	server.ListenAndServeTLS("", "")
}

func publicIP() (string, error) {
	const expectedHeader = "current address:"
	resp, err := http.Get("https://ipdetect.dnspark.com/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("https://ipdetect.dnspark.com returened %q", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if str := strings.ToLower(scanner.Text()); strings.HasPrefix(str, expectedHeader) {
			parts := strings.Split(str, ":")
			return strings.TrimSpace(parts[1]), nil
		}
	}

	return "", fmt.Errorf("Could not find %q", expectedHeader)
}

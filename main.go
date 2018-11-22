package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Missing hostname argument")
		os.Exit(-1)
	}
	domain := os.Args[1]
	if domain[:6] != "_esni." {
		domain = "_esni." + domain
	}
	fmt.Println("domain:", domain)
	records, err := net.LookupTXT(domain)
	if err != nil {
		log.Fatalf("Failed DNS lookup: %v", err)
	}
	// there can be multiple TXT records
	for _, record := range records {
		data, err := base64.StdEncoding.DecodeString(record)
		if err != nil {
			log.Fatalf("Failed to base64 decode TXT record: %v", err)
		}

		k, err := parseESNIKeys(data)
		if err != nil {
			log.Fatal(err)
		}
		k.Print(os.Stdout)
	}
}

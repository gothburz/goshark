package main

import (
	"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	// COMMAND-LINE ARGUMENTS
	app = kingpin.New("goshark", "golang pcap manipulation application.")
	// GET
	// - URI
	getCommand    = app.Command("get", "Get something from a PCAP.")
	getURICommand = getCommand.Command("uri", "URI Subcommand.")
	uriPCAP       = getURICommand.Arg("PCAP File", "PCAP to extract URI(s) from.").Required().String()
)

func getPCAPPath(relativePath string) (pcapPath string) {
	pcapPath, err := filepath.Abs(*uriPCAP)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// EXTRACT URI CASE
	case getURICommand.FullCommand():
		fmt.Println(app.Name, getURICommand.FullCommand())
		if uriPCAP != nil {
			pcapPath := getPCAPPath(*uriPCAP)
			tshark := exec.Command("tshark", "-r"+pcapPath,
				"-Y", "(http.request) && (tcp.stream)",
				"-T", "fields",
				"-e", "tcp.stream",
				"-e", "http.request.full_uri",
				"-E", "separator=/s")
			tshark.Stdout = os.Stdout
			tshark.Stderr = os.Stderr
			err := tshark.Run()
			if err != nil {
				log.Fatalf("goshark failed with %s\n", err)
			}
		}
	}
}

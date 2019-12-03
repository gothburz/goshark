package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	// COMMAND-LINE ARGUMENTS
	app = kingpin.New("goshark", "golang pcap manipulation application.")

	getCommand = app.Command("get", "Get something from a PCAP.")

	// get URI
	getURICommand = getCommand.Command("uri", "URI Command")
	uriPCAP       = getURICommand.Arg("PCAP File", "PCAP to extract URI(s) from.").Required().String()

	// get HOST
	getHostCommand = getCommand.Command("host", "HOST Command")
	hostPCAP       = getHostCommand.Arg("PCAP File", "PCAP to extract Host(s) from.").Required().String()
)

func getPCAPPath(relativePath string) (pcapPath string) {
	pcapPath, err := filepath.Abs(relativePath)
	if err != nil {
		log.Fatal(err)
	}
	return pcapPath
}

func main() {
	app.HelpFlag.Short('h')
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// GET URI CASE
	case getURICommand.FullCommand():
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
	// GET HOST CASE
	case getHostCommand.FullCommand():
		if hostPCAP != nil {
			pcapPath := getPCAPPath(*hostPCAP)
			tshark := exec.Command("tshark", "-r"+pcapPath,
				"-Y", "(http.request) && (tcp.stream)",
				"-T", "fields",
				"-e", "tcp.stream",
				"-e", "http.host",
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

package main

import (
	"bytes"

	//"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	// COMMAND-LINE ARGUMENTS
	app = kingpin.New("goshark", "golang pcap manipulation application.")

	getCommand = app.Command("get", "Get something from a PCAP.")
	/*
				HTTP Protocol

		        This sub-command gets HTTP protocol specific data:
					$ ./goshark get http <uri|host|user-agent|uri-params> [<flags>] <PCAP File>

	*/
	httpSubCommand = getCommand.Command("http", "HTTP Protocol.")

	// get URI
	getURICommand       = httpSubCommand.Command("uri", "URI Command")
	getUriPCAP          = getURICommand.Arg("PCAP File", "PCAP to extract URI(s) from.").Required().String()
	getURIReqMethodFlag = getURICommand.Flag("method", "Returns HTTP Method.").Bool()

	// get HOST
	getHostCommand = getCommand.Command("host", "HOST Command")
	hostPCAP       = getHostCommand.Arg("PCAP File", "PCAP to extract Host(s) from.").Required().String()

	// get USER-AGENT
	getUserAgentCommand = getCommand.Command("user-agent", "USER-AGENT Command")
	userAgentPCAP       = getUserAgentCommand.Arg("PCAP FIle", "PCAP to extract Host(s) from.").Required().String()

	// get URI PARAMS
	getURIParamsCommand = getCommand.Command("uri-params", "URI PARAMETER Command")
	uriParamsPCAP       = getURIParamsCommand.Arg("PCAP File", "PCAP to extract URI Parameter(s) from.").Required().String()
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
		if getUriPCAP != nil {
			pcapPath := getPCAPPath(*getUriPCAP)
			if *getURIReqMethodFlag == true {
				tshark := exec.Command("tshark",
					"-r"+pcapPath,
					"-Y", "(http.request) && (http.request.method) && (tcp.stream) && (frame.number)",
					"-T", "fields",
					"-e", "http.request.method",
					"-e", "http.request.full_uri",
					"-E", "separator=/s")
				awk := exec.Command("awk", "BEGIN { OFS = \"\\\n\"; ORS = \"\\n\\n\"} "+
					"{$1 = \"http.request.method == \" $1; "+
					"$2 = \"http.request.full_uri == \" \"\\x22\"$2\"\\x22\"; print }")

				r, w := io.Pipe()
				tshark.Stdout = w
				awk.Stdin = r

				var b2 bytes.Buffer
				awk.Stdout = &b2

				tshark.Start()
				awk.Start()
				tshark.Wait()
				w.Close()
				awk.Wait()
				io.Copy(os.Stdout, &b2)
			} else {
				tshark := exec.Command("tshark",
					"-r"+pcapPath,
					"-Y", "(http.request) && (http.request.method) && (tcp.stream) && (frame.number)",
					"-T", "fields",
					"-e", "http.request.full_uri",
					"-E", "separator=/s")
				awk := exec.Command("awk", "BEGIN { OFS = \"\\n\"; ORS = \"\\n\"} "+
					"{$1 = \"http.request.full_uri == \" \"\\x22\"$1\"\\x22\"; print }")

				r, w := io.Pipe()
				tshark.Stdout = w
				awk.Stdin = r

				var b2 bytes.Buffer
				awk.Stdout = &b2

				tshark.Start()
				awk.Start()
				tshark.Wait()
				w.Close()
				awk.Wait()
				io.Copy(os.Stdout, &b2)
			}
		}
	// GET HOST CASE
	case getHostCommand.FullCommand():
		if hostPCAP != nil {
			pcapPath := getPCAPPath(*hostPCAP)
			tshark := exec.Command("tshark", "-r"+pcapPath,
				"-Y", "(http.request) && (tcp.stream) && (frame.number)",
				"-T", "fields",
				"-e", "frame.number",
				"-e", "tcp.stream",
				"-e", "http.host",
				"-E", "separator=/s")

			awk := exec.Command("awk", "BEGIN { OFS = \"\\,\"} "+
				"{ $1 = \"frame.number==\" $1; "+
				"  $2 = \"tcp.stream==\" $2; "+
				"  $1 = \"http.host==\" \"\\x22\"$1\"\\x22\"; print }")

			r, w := io.Pipe()
			tshark.Stdout = w
			awk.Stdin = r

			var b2 bytes.Buffer
			awk.Stdout = &b2

			tshark.Start()
			awk.Start()
			tshark.Wait()
			w.Close()
			awk.Wait()
			io.Copy(os.Stdout, &b2)
		}

	// GET USER-AGENT CASE
	case getUserAgentCommand.FullCommand():
		if userAgentPCAP != nil {
			pcapPath := getPCAPPath(*userAgentPCAP)
			tshark := exec.Command("tshark", "-r"+pcapPath,
				"-Y", "(http.request) && (tcp.stream)",
				"-T", "fields",
				"-e", "frame.number",
				"-e", "tcp.stream",
				"-e", "http.user_agent",
				"-E", "separator=/s")
			awk := exec.Command("awk", "{$1 = \"http.user_agent == \" \"\\x22\"$1\"\\x22\"; print }")

			r, w := io.Pipe()
			tshark.Stdout = w
			awk.Stdin = r

			var b2 bytes.Buffer
			awk.Stdout = &b2

			tshark.Start()
			awk.Start()
			tshark.Wait()
			w.Close()
			awk.Wait()
			io.Copy(os.Stdout, &b2)
		}
	// GET URI PARAMETERS CASE
	case getURIParamsCommand.FullCommand():
		if uriParamsPCAP != nil {
			pcapPath := getPCAPPath(*uriParamsPCAP)
			tshark := exec.Command("tshark", "-r"+pcapPath,
				"-Y", "(http.request) && (tcp.stream)",
				"-T", "fields",
				"-e", "tcp.stream",
				"-e", "http.request.uri.query.parameter",
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

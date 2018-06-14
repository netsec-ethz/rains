package main

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"net/http"

	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainsd"
)

var (
	debugAddr = flag.String("debug_addr", "[::1]:8080", "Address to listen on for debugging info server.")
	config    = flag.String("config", "", "Path to configuration file.")
	verbosity = flag.Int("verbosity", int(log.LvlDebug), "Verbosity of logging.")

	buildinfoHostname string
	buildinfoCommit   string
	buildinfoBranch   string
)

func statusHandler(w http.ResponseWriter, r *http.Request) {
	statusPage := `<!DOCTYPE html>
<head>
    <title>rainsd status</title>
</head>
<h1>Rainsd</h1>
<tt>Built at commit {{.Commit}}, branch {{.Branch}} on host {{.Host}}.</tt>
</html>
`
	tmpl, err := template.New("statusPage").Parse(statusPage)
	if err != nil {
		log.Warn(fmt.Sprintf("failed to parse template: %v", err))
		w.Write([]byte("Internal server error"))
		w.WriteHeader(500)
		return
	}
	b := bytes.NewBuffer(make([]byte, 0))
	err = tmpl.Execute(b, struct {
		Commit string
		Branch string
		Host   string
	}{
		buildinfoCommit,
		buildinfoBranch,
		buildinfoHostname,
	})
	if err != nil {
		log.Warn(fmt.Sprintf("failed to execute template: %v", err))
		w.Write([]byte("Internal server error"))
		w.WriteHeader(500)
		return
	}
	w.Write(b.Bytes())
}

func statusServer() {
	http.HandleFunc("/0/status", statusHandler)
	if err := http.ListenAndServe(*debugAddr, nil); err != nil {
		log.Warn(fmt.Sprintf("HTTP server error: %v", err))
	}
}

func main() {
	flag.Parse()

	log.Info("Starting rains server...")

	if *config == "" {
		log.Warn("Path to config file must be specified.")
		return
	}
	if err := rainsd.InitServer(*config, *verbosity); err != nil {
		log.Error(fmt.Sprintf("Failed to start server: %v", err))
	}
	go statusServer()
	rainsd.Listen()
}

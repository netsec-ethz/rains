package main

import (
	"bytes"
	"flag"
	"html/template"
	"net/http"

	"github.com/golang/glog"
	log "github.com/inconshreveable/log15"
	"github.com/netsec-ethz/rains/rainsd"
)

var (
	debugAddr = flag.String("debug_addr", "[::1]:8080", "Address to listen on for debugging info server.")
	config    = flag.String("config", "", "Path to configuration file.")
	verbosity = flag.Int("verbosity", int(log.LvlDebug), "Verbosity of logging.")

	buildinfo_hostname string
	buildinfo_commit   string
	buildinfo_branch   string
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
		glog.Warningf("failed to parse template: %v", err)
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
		buildinfo_commit,
		buildinfo_branch,
		buildinfo_hostname,
	})
	if err != nil {
		glog.Warningf("failed to execute template: %v", err)
		w.Write([]byte("Internal server error"))
		w.WriteHeader(500)
		return
	}
	w.Write(b.Bytes())
}

func statusServer() {
	http.HandleFunc("/0/status", statusHandler)
	if err := http.ListenAndServe(*debugAddr, nil); err != nil {
		glog.Warningf("HTTP server error: %v", err)
	}
}

func main() {
	flag.Parse()

	glog.Info("Starting rains server...")

	if *config == "" {
		glog.Fatalf("Path to config file must be specified.")
	}
	if err := rainsd.InitServer(*config, *verbosity); err != nil {
		glog.Fatalf("Failed to start server: %v", err)
	}
	go statusServer()
	rainsd.Listen()
}

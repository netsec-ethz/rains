package rainsd

import (
	"rains/rainslib"
	"testing"
)

func TestGetIPAddrandPort(t *testing.T) {
	var tests = []struct {
		input rainsdConfig
		want  rainslib.ConnInfo
	}{
	/*{rainsdConfig{ServerIPAddr: net.ParseIP("127.0.0.1"), ServerPort: 1022, MaxConnections: 1000, TLSCertificateFile: "server.crt", TLSPrivateKeyFile: "server.key"},
	rainslib.ConnInfo{Type: 1, IPAddr: net.ParseIP("127.0.0.1"), Port: 1022}},*/
	}
	for _, test := range tests {
		Config = test.input
		/*if got := getIPAddrandPort(); got != test.want {
			t.Errorf("GetIPAddrandPort() on %v = %v", test.input, got)
		}*/
	}
}

//We use default values for now in case of an error
/*func TestGetIPAddrandPortError(t *testing.T) {
	var tests = []rainsdConfig{
		rainsdConfig{ServerIPAddr: "", ServerPort: 0, MaxConnections: 1000, CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		rainsdConfig{ServerIPAddr: "127.0.0.1", ServerPort: 0, MaxConnections: 1000, CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
		rainsdConfig{ServerIPAddr: "", ServerPort: 1022, MaxConnections: 1000, CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
	}
	for _, test := range tests {
		Config = test
		if _, err := getIPAddrandPort(); err == nil {
			t.Errorf("GetIPAddrandPort() on %v = nil", test)
		}
	}
}*/

/*func TestParseRemoteAddr(t *testing.T) {
	var tests = []struct {
		input string
		want  rainslib.ConnInfo
	}{
		{"127.0.0.1:1022",
			ConnInfo{Type: 1, IPAddr: net.ParseIP("127.0.0.1"), Port: 1022}},
	}
	for _, test := range tests {
		if got := parseRemoteAddr(test.input); got.Port != test.want.Port || got.Type != test.want.Type || !bytes.Equal(got.IPAddr, test.want.IPAddr) {
			t.Errorf("parseRemoteAddr(%s) = %v", test.input, got)
		}
	}
}*/

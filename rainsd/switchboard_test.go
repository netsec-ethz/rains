package rainsd

import "testing"

func TestGetIPAddrandPort(t *testing.T) {
	var tests = []struct {
		input rainsdConfig
		want  ConnInfo
	}{
		{rainsdConfig{ServerIPAddr: "127.0.0.1", ServerPort: 1022, MaxConnections: 1000, CertificateFile: "server.crt", PrivateKeyFile: "server.key"},
			ConnInfo{Type: 1, IPAddr: "127.0.0.1", Port: 1022}},
	}
	for _, test := range tests {
		Config = test.input
		if got, err := getIPAddrandPort(); got != test.want || err != nil {
			t.Errorf("GetIPAddrandPort() on %v = %v", test.input, got)
		}
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

func TestParseRemoteAddr(t *testing.T) {
	var tests = []struct {
		input string
		want  ConnInfo
	}{
		{"127.0.0.1:1022",
			ConnInfo{Type: 1, IPAddr: "127.0.0.1", Port: 1022}},
	}
	for _, test := range tests {
		if got := parseRemoteAddr(test.input); got != test.want {
			t.Errorf("parseRemoteAddr(%s) = %v", test.input, got)
		}
	}
}

// Package configs contains templates for the configuration files to be used in testing.
package configs

import (
	"bytes"
	"fmt"
	"text/template"
)

var (
	pubTmpl = `
    :Z: . . [
        :S: [
            {{ range .L2TLDs }}
                :A: {{ .TLD }} [ :deleg: ed25519 {{ .PubKey }} :redir: ns.{{ .TLD }}. ]
                :A: ns.{{ .TLD }} [ :srv: ns1.{{ .TLD }}. {{ .RedirPort }} 10 ]
                :A: ns1.{{ .TLD }} [ :ip6: ::1 ]
            {{ end }}
        ]
    ]
`
	tldPubTmpl = `
    :Z: {{ .TLD }}. . [
        :S: [
            {{ range .Domains }}
                :A: {{ .Domain }} [ :ip4: {{ .IP4 }} ]
            {{ end }}
        ]
    ]
`

	pubConfTmpl = `
{
    "AssertionValidSince": 0,
    "DelegationValidSince": 0,
    "ShardValidSince": 0,
    "ZoneValidSince": 0,
    "AssertionValidUntil": 86400,
    "DelegationValidUntil": 86400,
    "ShardValidUntil": 86400,
    "ZoneValidUntil": 86400,
    "MaxAssertionsPerShard": 5,
    "ServerAddresses": [
        {"Type":"TCP", "TCPAddr":{"IP":"::1","Port":{{ .Port }},"Zone":""}}
    ],
    "ZoneFilePath":"{{ .ZoneFilePath }}",
    "ZonePrivateKeyPath": "{{ .PrivateKeyPath }}"
}
    `

	serverTmpl = `
{
    "RootZonePublicKeyPath":        "{{.RootZonePublicKeyPath}}",
    "ServerAddress":                {
                                        "Type":     "TCP",
                                        "TCPAddr":  {
                                                        "IP":"::1",
                                                        "Port":{{.ListenPort}},
                                                        "Zone":""
                                                    }
                                    },
    "MaxConnections":               1000,
    "KeepAlivePeriod":              60,
    "TCPTimeout":                   300,
    "TLSCertificateFile":           "{{.TLSCertificateFile}}",
    "TLSPrivateKeyFile":            "{{.TLSPrivateKeyFile}}",
    "MaxMsgByteLength":             65536,
    "PrioBufferSize":               1000,
    "NormalBufferSize":             100000,
    "PrioWorkerCount":              2,
    "NormalWorkerCount":            10,
    "ActiveTokenCacheSize":         1000,
    "ZoneKeyCacheSize":             1000,
    "ZoneKeyCacheWarnSize":         750,
    "MaxPublicKeysPerZone":         5,
    "PendingKeyCacheSize":          1000,
    "AssertionCacheSize":           10000,
    "PendingQueryCacheSize":        1000,
    "RedirectionCacheSize":         1000,
    "RedirectionCacheWarnSize":     750,
    "CapabilitiesCacheSize":        50,
    "NotificationBufferSize":       20,
    "NotificationWorkerCount":      2,
    "PeerToCapCacheSize":           1000,
    "Capabilities":                 ["urn:x-rains:tlssrv"],
    "InfrastructureKeyCacheSize":   10,
    "ExternalKeyCacheSize":         5,
    "DelegationQueryValidity":      5,
    "NegativeAssertionCacheSize":   500,
    "AddressQueryValidity":         5,
    "QueryValidity":                5,
    "MaxCacheValidity":             {
                                        "AssertionValidity": 720,
                                        "ShardValidity": 720,
                                        "ZoneValidity": 720,
                                        "AddressAssertionValidity": 720,
                                        "AddressZoneValidity": 720
                                    },
    "ReapVerifyTimeout":            1800,
    "ReapEngineTimeout":            1800,
    "ContextAuthority":             ["{{.ContextAuthority}}"],
    "ZoneAuthority":                ["{{.ZoneAuthority}}"]
}
    `
)

type TLDPubParams struct {
	TLD     string
	Domains []struct {
		Domain string
		IP4    string
	}
}

func (tpp *TLDPubParams) Config() (string, error) {
	tmpl, err := template.New("tldPubTmpl").Parse(tldPubTmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse zonefile template: %v", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0))
	if err := tmpl.Execute(buf, tpp); err != nil {
		return "", fmt.Errorf("failed to execute zonefile template: %v", err)
	}
	return buf.String(), nil
}

type RootPubConf struct {
	Port           uint
	ZoneFilePath   string
	PrivateKeyPath string
}

func (rpc *RootPubConf) PubConfig() (string, error) {
	tmpl, err := template.New("rootPubConf").Parse(pubConfTmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse config template: %v", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0))
	if err := tmpl.Execute(buf, rpc); err != nil {
		return "", fmt.Errorf("failed to execute config template: %v", err)
	}
	return buf.String(), nil
}

// RootPubParams defines the variables to substitute into
// the configuration for the root rainsPub instance.
type RootPubParams struct {
	L2TLDs []struct {
		TLD       string
		PubKey    string
		RedirPort uint
	}
}

func (rpp *RootPubParams) ZoneFile() (string, error) {
	tmpl, err := template.New("rootPubParams").Parse(pubTmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse config template: %v", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0))
	if err := tmpl.Execute(buf, rpp); err != nil {
		return "", fmt.Errorf("failed to execute config template: %v", err)
	}
	return buf.String(), nil
}

type ServerConfigParams struct {
	ListenPort            uint
	RootZonePublicKeyPath string
	TLSCertificateFile    string
	TLSPrivateKeyFile     string
	ContextAuthority      string
	ZoneAuthority         string
}

func (scp *ServerConfigParams) ServerConfig() (string, error) {
	tmpl, err := template.New("serverConfig").Parse(serverTmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse config template: %v", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0))
	if err := tmpl.Execute(buf, scp); err != nil {
		return "", fmt.Errorf("failed to execute config template: %v", err)
	}
	return buf.String(), nil
}

package parser

import "testing"

func TestWordScanner(t *testing.T) {
	var tests = []struct {
		input      string
		scansCalls int
		lineNumber int
		text       string
	}{
		{"Hello my name", 2, 1, "my"},
		{"Hello\tmy\tname", 2, 1, "my"},
		{"Hello\tmy\nname", 2, 1, "my"},
		{"Hello my\nname", 3, 2, "name"},
		{"Hello\tmy\n\nname", 3, 3, "name"},
		{"Hello\tmy\n\nname \t\nis", 4, 4, "is"},
		{"Hello\tmy\n\nname \t\nis", 5, 5, ""},
	}
	for _, test := range tests {
		scanner := NewWordScanner([]byte(test.input))
		for i := 0; i < test.scansCalls; i++ {
			scanner.Scan()
		}
		if scanner.Text() != test.text {
			t.Errorf("Wrong test. expected=%s, actual=%s", test.text, scanner.Text())
		}
		if scanner.LineNumber() != test.lineNumber {
			t.Errorf("Line number incorrect. expected=%d, actual=%d", test.lineNumber, scanner.LineNumber())
		}
	}
}

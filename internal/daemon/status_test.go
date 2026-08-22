package daemon

import "testing"

func TestMaskServer(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":      "203.0.x.x",
		"your.server.com":  "y***.com",
		"a.b":              "a***.b",
		"deep.sub.example": "d***.example",
	}
	for in, want := range cases {
		if got := MaskServer(in); got != want {
			t.Errorf("MaskServer(%q) = %q, want %q", in, got, want)
		}
	}
}

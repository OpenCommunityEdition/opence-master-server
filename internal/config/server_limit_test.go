package config

import (
	"flag"
	"testing"
)

func TestMaxServers(t *testing.T) {
	for _, value := range []string{"0", "1", "20", "-1", "abc", "999999999999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			values := Flags(flag.NewFlagSet("test", flag.ContinueOnError))
			for _, o := range Options {
				*values[o.Env] = o.Default
			}
			*values["MASTER_MAX_SERVERS"] = value
			c, err := Load(values)
			valid := value == "0" || value == "1" || value == "20"
			if valid && (err != nil || c.MaxServers < 0) {
				t.Fatalf("%+v %v", c, err)
			}
			if !valid && err == nil {
				t.Fatal("invalid cap accepted")
			}
		})
	}
}

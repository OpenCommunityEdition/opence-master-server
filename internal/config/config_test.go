package config

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// A secret's variable is never a flag's default (the help would show it),
// and is read all the same.
func TestSecretsNotInTheHelp(t *testing.T) {
	for _, env := range []string{"MASTER_ADMIN_TOKEN", "MASTER_DISCORD_TOKEN", "MASTER_DISCORD_CLIENT_SECRET",
		"MASTER_SMTP_PASSWORD"} {
		t.Setenv(env, "secret-value-of-"+env)
	}
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	values := Flags(set)
	var help bytes.Buffer
	set.SetOutput(&help)
	set.PrintDefaults()
	if strings.Contains(help.String(), "secret-value-of") {
		t.Fatalf("a secret in the help:\n%s", help.String())
	}
	c, err := Load(values)
	if err != nil {
		t.Fatal(err)
	}
	if c.DiscordClientSecret != "secret-value-of-MASTER_DISCORD_CLIENT_SECRET" || c.DiscordToken == "" {
		t.Fatalf("%+v", c)
	}
}

func TestNetlistOptions(t *testing.T) {
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	values := Flags(set)
	for _, o := range Options {
		*values[o.Env] = o.Default
	}
	c, err := Load(values)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Netlist || len(c.NetlistASNURLs) != 2 || len(c.NetlistListURLs) != 2 || c.NetlistTorURL == "" ||
		c.LinkMaxKeys != 3 || c.PassTTL.Hours() != 72 {
		t.Fatalf("%+v", c)
	}
	*values["MASTER_NETLIST_LIST_URLS"] = "http://example.org/list.txt"
	if _, err := Load(values); err == nil {
		t.Fatal("a plain HTTP source beyond loopback taken")
	}
	*values["MASTER_NETLIST_LIST_URLS"] = "http://127.0.0.1:8080/list.txt, https://example.org/b.txt"
	*values["MASTER_NETLIST_TOR_URL"] = ""
	*values["MASTER_NETLIST"] = "off"
	c, err = Load(values)
	if err != nil || len(c.NetlistListURLs) != 2 || c.NetlistTorURL != "" || c.Netlist {
		t.Fatalf("%+v %v", c, err)
	}
}

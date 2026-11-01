package sshconfig_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/Br0ce/sshconfig"
)

const exampleConfig = `
Host web
    HostName web.example.com
    User deploy
    Port 2222
    IdentityFile /home/max/.ssh/id_web

Host cmp*
    HostName %h.cluster.example.com

Host *
    IdentityFile ~/.ssh/id_%r_%h
`

// exampleLocal stands in for the current user and host, so the output does not depend on
// the machine running the example.
var exampleLocal = sshconfig.WithLocalAs(sshconfig.Local{User: "max", Home: "/home/max"})

// Programs usually read the standard files with UserConfig and SystemConfig. Here the
// config is read from a string.
func Example() {
	cfg, err := sshconfig.Decode(strings.NewReader(exampleConfig))
	if err != nil {
		log.Fatal(err)
	}

	web := sshconfig.Lookup("web", sshconfig.WithUserConfig(cfg), exampleLocal)
	for _, key := range []string{"HostName", "User", "Port", "IdentityFile"} {
		v, err := web.Get(key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(key, v)
	}

	cmp := sshconfig.Lookup("cmp1", sshconfig.WithUserConfig(cfg), exampleLocal)
	fmt.Println(cmp.GetRaw("HostName"))
	for _, key := range []string{"HostName", "IdentityFile"} {
		v, err := cmp.Get(key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(key, v)
	}
	// Output:
	// HostName web.example.com
	// User deploy
	// Port 2222
	// IdentityFile /home/max/.ssh/id_web
	// %h.cluster.example.com
	// HostName cmp1.cluster.example.com
	// IdentityFile /home/max/.ssh/id_max_cmp1.cluster.example.com
}

func ExampleValues_Set() {
	cfg, err := sshconfig.Decode(strings.NewReader(exampleConfig))
	if err != nil {
		log.Fatal(err)
	}

	vals := sshconfig.Lookup("cmp1", sshconfig.WithUserConfig(cfg), exampleLocal).Set("User", "admin")
	file, err := vals.Get("IdentityFile")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(file)
	// Output:
	// /home/max/.ssh/id_admin_cmp1.cluster.example.com
}

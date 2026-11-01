package sshconfig

import (
	"slices"
	"strings"
	"testing"
)

func TestConfigLookup(t *testing.T) {
	tests := []struct {
		file, alias, key, want string
	}{
		{"basic", "web", "HostName", "web01.example.com"},
		{"basic", "web", "Port", "2222"},
		{"basic", "web", "User", "alice"},
		{"basic", "db", "hostname", "db01.example.com"},
		{"basic", "db", "Port", "2200"},
		{"basic", "db", "User", "bob"},
		{"basic", "build server", "HostName", "ci.example.com"},
		{"basic", "ci", "IdentityFile", "~/.ssh/ci key"},
		{"basic", "unknown", "HostName", ""},

		{"patterns", "prod-api", "HostName", "%h.corp.example.com"},
		{"patterns", "prod-api", "User", "ops"},
		{"patterns", "prod-api", "Port", "22"},
		{"patterns", "PROD-API", "User", "ops"},
		{"patterns", "prod-legacy", "HostName", "legacy.example.com"},
		{"patterns", "prod-legacy", "User", "default"},
		{"patterns", "lab1", "HostName", "%h.lab.example.com"},
		{"patterns", "lab1", "Port", "2022"},
		{"patterns", "lab10", "HostName", ""},
		{"patterns", "lab10", "Port", "22"},
		{"patterns", "db.internal", "ProxyJump", "bastion.example.com"},

		{"include", "work", "HostName", "work.example.com"},
		{"include", "work", "User", "worker"},
		{"include", "nas", "HostName", "nas.example.com"},
		{"include", "jump", "HostName", "jump.example.com"},
		{"include", "jump", "Port", "2201"},
		{"include", "jump", "User", ""},
		{"include", "other", "HostName", "other.example.com"},
		{"include", "other", "Port", "2201"},
		{"include", "unknown", "Port", ""},

		{"match", "app", "HostName", "app.prod.example.com"},
		{"match", "app", "User", "prod"},
		{"match", "app", "Port", "2300"},
		{"match", "app", "IdentityFile", ""},
		{"match", "staging-web", "HostName", "%h.staging.example.com"},
		{"match", "staging-web", "User", "fallback"},
		{"match", "web.example.com", "User", "fallback"},
		{"match", "web.example.com", "Port", "22"},
		{"match", "web.example.com", "IdentityFile", ""},
	}
	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.alias+"/"+tt.key, func(t *testing.T) {
			if got := lookup(t, tt.file, tt.alias).GetRaw(tt.key); got != tt.want {
				t.Errorf("GetRaw(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	user, err := decodeTestdata(t, "with-system")
	if err != nil {
		t.Fatal(err)
	}
	system, err := DecodeFile("testdata/etc/ssh/ssh_config", WithHome(home))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		alias, key, want string
	}{
		// Match host in the system config sees the HostName from the user config.
		{"app", "HostName", "app.corp.example.com"},
		{"app", "ProxyJump", "bastion.corp.example.com"},
		{"app", "User", "sysdefault"},
		// The user config wins, the system config fills in the rest.
		{"db.corp.example.com", "User", "dba"},
		{"db.corp.example.com", "Port", "2200"},
		{"db.corp.example.com", "IdentityFile", "~/.ssh/corp_ed25519"},
		{"other", "User", "sysdefault"},
		{"other", "SendEnv", "LANG LC_*"},
	}
	for _, tt := range tests {
		got := Lookup(tt.alias, WithUserConfig(user), WithSystemConfig(system)).GetRaw(tt.key)
		if got != tt.want {
			t.Errorf("Lookup(%q).GetRaw(%q) = %q, want %q", tt.alias, tt.key, got, tt.want)
		}
		// The user config comes first whatever the order of the options.
		got = Lookup(tt.alias, WithSystemConfig(system), WithUserConfig(user)).GetRaw(tt.key)
		if got != tt.want {
			t.Errorf("Lookup(%q) with the system config first: GetRaw(%q) = %q, want %q", tt.alias, tt.key, got, tt.want)
		}
	}
}

func TestLookupWithoutConfigs(t *testing.T) {
	if got := Lookup("web").GetRaw("HostName"); got != "" {
		t.Errorf("GetRaw(HostName) = %q, want empty", got)
	}
}

func TestValuesGetRaw(t *testing.T) {
	s := lookup(t, "basic", "web")
	tests := []struct {
		key, want string
	}{
		{"HostName", "web01.example.com"},
		{"hostname", "web01.example.com"},
		{"HOSTNAME", "web01.example.com"},
		// The first value wins.
		{"Port", "2222"},
		{"ProxyJump", ""},
	}
	for _, tt := range tests {
		if got := s.GetRaw(tt.key); got != tt.want {
			t.Errorf("GetRaw(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestValuesGetAllRaw(t *testing.T) {
	s := lookup(t, "patterns", "prod-api")
	tests := []struct {
		key  string
		want []string
	}{
		{"IdentityFile", []string{"~/.ssh/%h_ed25519", "~/.ssh/id_ed25519"}},
		{"identityfile", []string{"~/.ssh/%h_ed25519", "~/.ssh/id_ed25519"}},
		{"Port", []string{"22"}},
		{"ProxyJump", nil},
	}
	for _, tt := range tests {
		if got := s.GetAllRaw(tt.key); !slices.Equal(got, tt.want) {
			t.Errorf("GetAllRaw(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestValuesGet(t *testing.T) {
	tests := []struct {
		alias, key, want string
	}{
		{"web", "HostName", "web.example.com"},
		{"web", "User", "max-admin"},
		{"web", "Port", "2222"},
		{"web", "IdentityFile", "/home/max/.ssh/web.example.com_max-admin"},
		// SHA-1 of %l%h%p%r%j.
		{"web", "ControlPath", "/home/max/.ssh/cm-33dfa43652aeb547765ff9432d35d32b829f37e2"},
		{"web", "ProxyCommand", "ssh -W web.example.com:2222 max-admin@gateway"},
		{"web", "UserKnownHostsFile", "/home/max/.ssh/known_hosts /home/max/.ssh/known_hosts2"},
		{"web", "RemoteCommand", "echo laptop laptop.example.org web 100%"},
		{"web", "SendEnv", "LC_%h"},
		{"web", "LocalCommand", ""},
		{"plain", "IdentityFile", "/home/max/.ssh/plain-22-max-"},
		{"plain", "RemoteCommand", "echo plain-key"},
		{"plain", "HostName", ""},
	}
	for _, tt := range tests {
		t.Run(tt.alias+"/"+tt.key, func(t *testing.T) {
			got, err := lookup(t, "tokens", tt.alias).Get(tt.key)
			if err != nil || got != tt.want {
				t.Errorf("Get(%q) = %q, %v, want %q", tt.key, got, err, tt.want)
			}
		})
	}
}

func TestValuesGetProxyJump(t *testing.T) {
	tests := []struct {
		alias, raw, want string
	}{
		{"multi", "admin@bastion.example.com:2222,jump.example.com", "admin@bastion.example.com:2222,jump.example.com"},
		{"tokens", "%r@bastion-%n.example.com:%p", "ops@bastion-tokens.example.com:2200"},
		// %h is the expanded HostName.
		{"internal-db", "jump-for-%h", "jump-for-internal-db.corp.example.com"},
		{"direct", "none", "none"},
		{"other", "default.example.com", "default.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			s := lookup(t, "proxyjump", tt.alias)
			if got := s.GetRaw("ProxyJump"); got != tt.raw {
				t.Errorf("GetRaw(ProxyJump) = %q, want %q", got, tt.raw)
			}
			got, err := s.Get("ProxyJump")
			if err != nil || got != tt.want {
				t.Errorf("Get(ProxyJump) = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}

func TestValuesGetErrors(t *testing.T) {
	tests := []struct {
		alias, key, want string
	}{
		{"bad-hostname", "HostName", "token %u not supported"},
		{"bad-proxy", "ProxyCommand", "token %d not supported"},
		{"bad-user", "User", "token %r not supported"},
		{"conn-only", "LocalCommand", "token %T not supported"},
		// An error in HostName fails every value using %h.
		{"bad-nested", "IdentityFile", "token %x not supported"},
		{"bad-trailing", "IdentityFile", "trailing %"},
	}
	for _, tt := range tests {
		t.Run(tt.alias+"/"+tt.key, func(t *testing.T) {
			_, err := lookup(t, "tokens", tt.alias).Get(tt.key)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Get(%q) error = %v, want it to contain %q", tt.key, err, tt.want)
			}
		})
	}
}

func TestValuesGetAll(t *testing.T) {
	s := lookup(t, "tokens", "web")
	got, err := s.GetAll("IdentityFile")
	want := []string{"/home/max/.ssh/web.example.com_max-admin", "/home/max/keys/web-1000"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("GetAll(IdentityFile) = %q, %v, want %q", got, err, want)
	}

	if got, err := s.GetAll("CertificateFile"); err != nil || got != nil {
		t.Errorf("GetAll(CertificateFile) = %q, %v, want nil", got, err)
	}

	if _, err := lookup(t, "tokens", "bad-nested").GetAll("IdentityFile"); err == nil {
		t.Error("GetAll(IdentityFile) error = nil, want an error")
	}
}

func TestValuesGetEmptyLocal(t *testing.T) {
	cfg, err := decodeTestdata(t, "tokens")
	if err != nil {
		t.Fatal(err)
	}
	s := Lookup("web", WithUserConfig(cfg), WithLocalAs(Local{}))

	// Values that need no local value expand as usual.
	tests := []struct {
		key, want string
	}{
		{"HostName", "web.example.com"},
		{"Port", "2222"},
		{"SendEnv", "LC_%h"},
	}
	for _, tt := range tests {
		got, err := s.Get(tt.key)
		if err != nil || got != tt.want {
			t.Errorf("Get(%q) = %q, %v, want %q", tt.key, got, err, tt.want)
		}
	}

	// ~ needs the local home directory, %u in User the local user, also for %r in
	// ProxyCommand, and %C the local host name.
	for _, key := range []string{"IdentityFile", "UserKnownHostsFile", "User", "ProxyCommand", "ControlPath"} {
		if _, err := s.Get(key); err == nil || !strings.Contains(err.Error(), "see WithLocalAs") {
			t.Errorf("Get(%q) error = %v, want a missing local value", key, err)
		}
	}
}

func TestLookupLocalDefault(t *testing.T) {
	cfg, err := decodeTestdata(t, "tokens")
	if err != nil {
		t.Fatal(err)
	}
	// Without WithLocalAs, the local side is the current user and host.
	got, err := Lookup("web", WithUserConfig(cfg)).Get("IdentityFile")
	if err != nil || strings.HasPrefix(got, "~") {
		t.Errorf("Get(IdentityFile) = %q, %v, want ~ expanded", got, err)
	}
}

func TestValuesSet(t *testing.T) {
	orig := lookup(t, "tokens", "web")
	s := orig.Set("port", "2022").Set("User", "%u-ops")

	tests := []struct {
		key, want string
	}{
		{"Port", "2022"},
		// A set value is not expanded.
		{"User", "%u-ops"},
		// %r and %p use the set values.
		{"IdentityFile", "/home/max/.ssh/web.example.com_%u-ops"},
		{"ProxyCommand", "ssh -W web.example.com:2022 %u-ops@gateway"},
	}
	for _, tt := range tests {
		got, err := s.Get(tt.key)
		if err != nil || got != tt.want {
			t.Errorf("Get(%q) = %q, %v, want %q", tt.key, got, err, tt.want)
		}
	}

	if got := orig.GetRaw("Port"); got != "2222" {
		t.Errorf("Set changed the original: GetRaw(Port) = %q, want %q", got, "2222")
	}
}

func TestLookupReadsLocalOnUse(t *testing.T) {
	calls := 0
	orig := localEnv
	localEnv = func() (Local, error) {
		calls++
		return local, nil
	}
	defer func() { localEnv = orig }()

	cfg, err := decodeTestdata(t, "tokens")
	if err != nil {
		t.Fatal(err)
	}
	s := Lookup("web", WithUserConfig(cfg))
	if _, err := s.Get("Port"); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("local side read %d times before a value needed it, want 0", calls)
	}

	// Copies made by Set share the local side, so it is read once.
	for _, vs := range []Values{s, s.Set("Port", "22"), s} {
		if _, err := vs.Get("IdentityFile"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("local side read %d times, want 1", calls)
	}
}

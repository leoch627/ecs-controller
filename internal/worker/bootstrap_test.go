package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Kori1c/ecs-controller/internal/store"
)

func TestBootstrapDefaultImageChangesPasswordAndRepairs(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var commands []string
	var newPassword, script string
	booting := true
	w := &Worker{Store: s, SSHRetryInterval: 1,
		RemoteExec: func(_ context.Context, addr, user, password, command, stdin string) (string, error) {
			if addr != "198.51.100.7:22" || user != "root" {
				t.Fatalf("unexpected login %s@%s", user, addr)
			}
			if booting {
				booting = false
				return "", errors.New("connection refused")
			}
			commands = append(commands, command)
			switch command {
			case "true":
				if password != "default-pass" {
					t.Fatalf("first login must use the image password, got %q", password)
				}
			case "chpasswd":
				newPassword = strings.TrimSuffix(strings.TrimPrefix(stdin, "root:"), "\n")
			case "sh -s":
				if password != newPassword {
					t.Fatalf("repair must log in with the new password")
				}
				script = stdin
			}
			return "", nil
		}}
	got, err := w.bootstrapDefaultImage(context.Background(), "198.51.100.7", 22, "root", "default-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got == "" || got != newPassword || got == "default-pass" {
		t.Fatalf("password was not replaced: got %q chpasswd %q", got, newPassword)
	}
	if strings.Join(commands, ",") != "true,chpasswd,sh -s" || !strings.Contains(script, "tcp_bbr") || !strings.Contains(script, "systemd-sysv") {
		t.Fatalf("unexpected commands %v / script %q", commands, script)
	}
}

func TestBootstrapKeepsNewPasswordWhenRepairFails(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w := &Worker{Store: s,
		RemoteExec: func(_ context.Context, _, _, _, command, _ string) (string, error) {
			if command == "sh -s" {
				return "E: Unable to locate package\n", errors.New("exit status 100")
			}
			return "", nil
		}}
	got, err := w.bootstrapDefaultImage(context.Background(), "198.51.100.7", 22, "root", "default-pass")
	if got == "" || err == nil || !strings.Contains(err.Error(), "Unable to locate package") {
		t.Fatalf("expected new password and repair error, got %q %v", got, err)
	}
}

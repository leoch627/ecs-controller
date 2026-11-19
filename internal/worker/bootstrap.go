package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// minimalDebianRepair fixes the default Debian 13 minimal image, whose apt
// policy blocks services from starting and which lacks the pieces systemd
// needs to load modules and sysctls at boot. It also turns on BBR.
const minimalDebianRepair = `set -e
export DEBIAN_FRONTEND=noninteractive

# 1. Let apt start services again
rm -f /usr/sbin/policy-rc.d
echo '#!/bin/sh' > /usr/sbin/policy-rc.d
echo 'exit 0' >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

# 2. Core components missing from the minimal image
apt-get update
apt-get install -y kmod procps init-system-helpers cron systemd-sysv

# 3. Unmask and enable the services that load modules and sysctls at boot
systemctl unmask systemd-modules-load systemd-sysctl cron
systemctl enable systemd-modules-load systemd-sysctl cron

# 4. Load BBR at boot
mkdir -p /etc/modules-load.d
echo "tcp_bbr" > /etc/modules-load.d/bbr.conf

# 5. BBR sysctls
cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

# 6. Apply
systemctl daemon-reload
systemctl restart systemd-modules-load systemd-sysctl cron
sysctl --system
`

const (
	bootstrapTimeout = 15 * time.Minute
	bootstrapSSHWait = 6 * time.Minute
)

// bootstrapDefaultImage logs in to a new instance built from the default
// image with the image's public default password, replaces that password with
// a random one and repairs the minimal environment. newPassword is set as soon
// as the password was changed, even if the repair that follows fails.
func (w *Worker) bootstrapDefaultImage(ctx context.Context, host string, port int, user, oldPassword string) (newPassword string, err error) {
	if host == "" {
		return "", fmt.Errorf("实例没有公网 IP")
	}
	if port <= 0 {
		port = 22
	}
	ctx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if err := w.waitSSH(ctx, addr, user, oldPassword); err != nil {
		return "", err
	}
	password := randomPassword()
	if _, err := w.remoteExec(ctx, addr, user, oldPassword, "chpasswd", user+":"+password+"\n"); err != nil {
		return "", fmt.Errorf("更换 root 密码失败: %w", err)
	}
	if output, err := w.remoteExec(ctx, addr, user, password, "sh -s", minimalDebianRepair); err != nil {
		return password, fmt.Errorf("修复极简环境失败: %w%s", err, outputTail(output))
	}
	return password, nil
}

// waitSSH retries until the instance has booted and sshd accepts the login.
func (w *Worker) waitSSH(ctx context.Context, addr, user, password string) error {
	deadline := time.Now().Add(bootstrapSSHWait)
	for {
		_, err := w.remoteExec(ctx, addr, user, password, "true", "")
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("SSH 登录 %s 失败: %w", addr, err)
		}
		sleep(ctx, w.sshRetryInterval())
	}
}

func (w *Worker) sshRetryInterval() time.Duration {
	if w.SSHRetryInterval > 0 {
		return w.SSHRetryInterval
	}
	return 5 * time.Second
}

func (w *Worker) remoteExec(ctx context.Context, addr, user, password, command, stdin string) (string, error) {
	if w.RemoteExec != nil {
		return w.RemoteExec(ctx, addr, user, password, command, stdin)
	}
	return sshExec(ctx, addr, user, password, command, stdin)
}

// sshExec runs one command over SSH with password login. The host key of a
// freshly created instance cannot be known in advance, so it is not checked.
func sshExec(ctx context.Context, addr, user, password, command, stdin string) (string, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	clientConn, channels, requests, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return "", err
	}
	client := ssh.NewClient(clientConn, channels, requests)
	defer client.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-done:
		}
	}()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var output tailBuffer
	session.Stdin = strings.NewReader(stdin)
	session.Stdout = &output
	session.Stderr = &output
	err = session.Run(command)
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return output.String(), err
}

func randomPassword() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw) + "Aa1!"
}

func outputTail(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}
	if lines := strings.Split(output, "\n"); len(lines) > 3 {
		output = strings.Join(lines[len(lines)-3:], " / ")
	}
	return "（" + output + "）"
}

// tailBuffer keeps only the last few KB of command output. stdout and stderr
// are copied by separate goroutines, hence the lock.
type tailBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Write(p)
	if over := t.buf.Len() - 4096; over > 0 {
		t.buf.Next(over)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.String()
}

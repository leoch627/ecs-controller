// gfw-probe runs on a machine inside mainland China. The panel asks it to
// open a TCP connection to an instance's public IP, which tells whether that
// IP is reachable from inside the country.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/reach"
)

func main() {
	token := strings.TrimSpace(os.Getenv("PROBE_TOKEN"))
	if len(token) < reach.MinTokenLength {
		log.Fatalf("请通过环境变量 PROBE_TOKEN 设置至少 %d 位的密钥，并在面板的「被墙检测」里填写同一个密钥", reach.MinTokenLength)
	}
	addr := strings.TrimSpace(os.Getenv("PROBE_ADDR"))
	if addr == "" {
		addr = ":8433"
	}
	server := &http.Server{Addr: addr, Handler: reach.Handler(token), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("gfw-probe listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

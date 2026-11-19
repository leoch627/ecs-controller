package dns

import (
	"strings"
	"sync"
)

// Records point at instances whose IP can change at any time, so they use the
// shortest TTL each provider accepts. Where the floor depends on the paid
// plan (Aliyun, DNSPod, Cloudflare Enterprise), the candidates are tried from
// shortest up and the first one the zone accepts is remembered.
var (
	ttlAliyun     = []int{1, 60, 600}          // 旗舰版 1 / 企业版 60 / 免费、个人版 600
	ttlDNSPod     = []int{1, 30, 60, 120, 600} // 旗舰 1 … 免费 600
	ttlHuawei     = []int{1}
	ttlCloudflare = []int{30, 60} // Enterprise 30, other plans 60
	// Route 53 bills every query, so it stops at 60s rather than 1s.
	ttlRoute53      = []int{60}
	ttlNameSilo     = []int{3600}
	ttlPorkbun      = []int{600}
	ttlGoDaddy      = []int{600}
	ttlDigitalOcean = []int{30}
)

// acceptedTTL remembers, per provider and zone, the index of the shortest
// candidate that was accepted, so later writes skip the rejected ones.
var acceptedTTL sync.Map

// withShortestTTL calls write with each candidate TTL, shortest first, moving
// on only when the provider rejects the TTL itself.
func withShortestTTL(provider, zone string, candidates []int, write func(ttl int) error) error {
	key := provider + "/" + normalizeName(zone)
	start := 0
	if index, ok := acceptedTTL.Load(key); ok && index.(int) < len(candidates) {
		start = index.(int)
	}
	var err error
	for i := start; i < len(candidates); i++ {
		if err = write(candidates[i]); err == nil {
			acceptedTTL.Store(key, i)
			return nil
		}
		if !isTTLError(err) {
			return err
		}
	}
	return err
}

func isTTLError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "ttl")
}

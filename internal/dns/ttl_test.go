package dns

import (
	"errors"
	"testing"
)

func TestWithShortestTTLStepsUpOnlyOnTTLErrors(t *testing.T) {
	var tried []int
	write := func(ttl int) error {
		tried = append(tried, ttl)
		if ttl < 600 {
			return errors.New("DomainRecordTTL.Invalid: TTL below plan minimum")
		}
		return nil
	}
	if err := withShortestTTL("test", "a.example", []int{1, 60, 600}, write); err != nil {
		t.Fatal(err)
	}
	if len(tried) != 3 || tried[2] != 600 {
		t.Fatalf("unexpected attempts: %v", tried)
	}
	// The accepted TTL is remembered for the zone.
	tried = nil
	if err := withShortestTTL("test", "a.example", []int{1, 60, 600}, write); err != nil || len(tried) != 1 || tried[0] != 600 {
		t.Fatalf("expected one attempt at 600, got %v err=%v", tried, err)
	}
	// Other errors are returned at once.
	tried = nil
	err := withShortestTTL("test", "b.example", []int{1, 60}, func(ttl int) error { tried = append(tried, ttl); return errors.New("forbidden") })
	if err == nil || len(tried) != 1 {
		t.Fatalf("expected immediate failure, got %v err=%v", tried, err)
	}
}

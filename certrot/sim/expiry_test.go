package sim

import (
	"testing"
	"time"

	"certrot/model"
)

// TestExpiryAndRecovery verifies that containers still holding the old cert
// flip to "expired" when its NotAfter passes, and that an auto-updating
// container returns to "ok" once rotation delivers a new cert.
func TestExpiryAndRecovery(t *testing.T) {
	cfg := Config{
		DataDir:       t.TempDir() + "/data",
		WorkloadCount: 12,
		NodeCount:     3,
		OldCertTTL:    3 * time.Second,
		NewCertTTL:    time.Hour,
		SampleEvery:   200 * time.Millisecond,
		VerifyEvery:   200 * time.Millisecond,
		Seed:          7,
		NodeSyncBase:  200 * time.Millisecond,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	defer s.Stop()

	// Wait beyond the v1 NotAfter with no rotation: every loaded cert is v1,
	// so every container must report expired.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if allExpired(s) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !allExpired(s) {
		t.Fatalf("not all containers marked expired after v1 NotAfter")
	}
	// The expiry event must be recorded on a sample container.
	c0 := s.Build().Containers[0]
	c0.Mu.RLock()
	sawEvent := false
	for _, e := range c0.Events {
		if e.Type == "expired" {
			sawEvent = true
		}
	}
	c0.Mu.RUnlock()
	if !sawEvent {
		t.Fatal("missing expired lifecycle event")
	}

	// Rotate: auto-updating containers reload v2 and recover to ok.
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		recovered := 0
		for _, c := range s.Build().Containers {
			c.Mu.RLock()
			if c.LoadedVersion == "v2" && c.Status == "ok" {
				recovered++
			}
			c.Mu.RUnlock()
		}
		if recovered == s.Scan().WillAutoUpdate {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// A predicted-never container must remain expired on v1 until restarted.
	var never *model.Container
	for _, c := range s.Build().Containers {
		if c.Prediction != nil && !c.Prediction.WillUpdate {
			never = c
			break
		}
	}
	if never == nil {
		t.Fatal("test fleet contained no never-updating container")
	}
	never.Mu.RLock()
	stuck := never.Status == "expired" && never.LoadedVersion == "v1"
	never.Mu.RUnlock()
	if !stuck {
		t.Fatalf("never-updating container unexpectedly healed: status=%s ver=%s",
			never.Status, never.LoadedVersion)
	}
	if err := s.Restart(never.ID); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		never.Mu.RLock()
		healed := never.LoadedVersion == "v2" && never.Status == "ok"
		never.Mu.RUnlock()
		if healed {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	never.Mu.RLock()
	healed := never.LoadedVersion == "v2" && never.Status == "ok"
	never.Mu.RUnlock()
	if !healed {
		t.Fatal("container did not recover after restart")
	}
}

func allExpired(s *Sim) bool {
	for _, c := range s.Build().Containers {
		c.Mu.RLock()
		exp := c.Status == "expired"
		c.Mu.RUnlock()
		if !exp {
			return false
		}
	}
	return true
}

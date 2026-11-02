package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/model"
)

func TestServerLimitConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	stores := []*Store{s, second}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := stores[i%len(stores)].PutServerLimited(&model.Server{ID: fmt.Sprint(i), PublisherID: fmt.Sprint(i), Updated: 100}, 3, 90)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrServerLimit) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatalf("accepted %d, want 3", accepted.Load())
	}
	live, err := s.LiveServers("", 90)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 3 {
		t.Fatalf("live %d", len(live))
	}
	// A reduced cap never destroys state or prevents existing live renewals.
	if err := s.PutServerLimited(&live[0], 1, 90); err != nil {
		t.Fatal(err)
	}
	if err := s.PutServerLimited(&model.Server{ID: "new", Updated: 100}, 1, 90); !errors.Is(err, ErrServerLimit) {
		t.Fatalf("over cap: %v", err)
	}
	// Closed records release capacity without being deleted.
	for _, v := range live {
		if err := s.CloseServer(v.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutServerLimited(&model.Server{ID: "new", Updated: 100}, 1, 90); err != nil {
		t.Fatal(err)
	}
	if err := s.PutServerLimited(&live[0], 1, 90); !errors.Is(err, ErrServerLimit) {
		t.Fatalf("reopen: %v", err)
	}
	// Expiry releases capacity, but an expired record cannot bypass a full cap.
	if err := s.PutServerLimited(&model.Server{ID: "fresh", Updated: 200}, 1, 190); err != nil {
		t.Fatal(err)
	}
	if err := s.PutServerLimited(&model.Server{ID: "new", Updated: 200}, 1, 190); !errors.Is(err, ErrServerLimit) {
		t.Fatalf("expired: %v", err)
	}
	if err := s.PutServerLimited(&model.Server{ID: "unlimited", Updated: 200}, 0, 190); err != nil {
		t.Fatal(err)
	}
}

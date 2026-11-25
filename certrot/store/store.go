// Package store is the simulated apiserver: versioned Secret/ConfigMap
// objects. A rotation is simply putting a new version of an object; nodes
// only observe it on their next sync.
package store

import (
	"sync"
	"time"
)

// ObjectKey identifies one key inside one secret/configmap object.
type ObjectKey struct {
	Name string
	Key  string
}

// Material is one rendered version of an object key.
type Material struct {
	Version   string // v1, v2, ...
	RV        int64  // monotonic resource version
	CertPEM   []byte // PEM-encoded leaf certificate
	KeyPEM    []byte
	EnvB64    string    // base64 DER, used for env injection
	Serial    string    // certificate serial number (decimal)
	NotAfter  time.Time // cert expiry
	UpdatedAt time.Time
}

type objectState struct {
	current *Material
	history []*Material
}

// Store is a tiny in-memory apiserver.
type Store struct {
	mu sync.Mutex
	m  map[ObjectKey]*objectState
}

// New creates an empty store.
func New() *Store {
	return &Store{m: make(map[ObjectKey]*objectState)}
}

// Put writes a new version of an object key.
func (s *Store) Put(k ObjectKey, mat *Material) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[k]
	if !ok {
		st = &objectState{}
		s.m[k] = st
	}
	mat.UpdatedAt = time.Now()
	st.current = mat
	st.history = append(st.history, mat)
}

// Current returns the latest version of an object key.
func (s *Store) Current(k ObjectKey) *Material {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.m[k]; ok {
		return st.current
	}
	return nil
}

// AllCurrent returns a snapshot of every object key's current material.
func (s *Store) AllCurrent() map[ObjectKey]*Material {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[ObjectKey]*Material, len(s.m))
	for k, st := range s.m {
		out[k] = st.current
	}
	return out
}

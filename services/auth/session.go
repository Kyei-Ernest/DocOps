package auth

import (
    "sync"
    "time"
)

type Session struct {
    UserID    string
    KEK       []byte
    ExpiresAt time.Time
}

type SessionStore struct {
    mu       sync.RWMutex
    sessions map[string]*Session
}

func NewSessionStore() *SessionStore {
    return &SessionStore{
        sessions: make(map[string]*Session),
    }
}

func (s *SessionStore) Save(token string, session *Session) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.sessions[token] = session
}

func (s *SessionStore) Get(token string) (*Session, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    session, ok := s.sessions[token]
    if !ok {
        return nil, false
    }
    if time.Now().After(session.ExpiresAt) {
        return nil, false
    }
    return session, true
}

func (s *SessionStore) Delete(token string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.sessions, token)
}
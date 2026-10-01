package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// These tests pin the lifecycle of the two enclave-backed caches (Local Codex
// review of #47): expired entries must be reclaimed before a new entry is
// allocated, so a locked-memory budget filled with dead entries cannot wedge the
// cache, and nothing may be inserted once the cache is closed.

// fakeClock is a manually advanced clock, so expiry is exercised without
// waiting on real time.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// recordingAllocator allocates from a real go-enclave Allocator — so a budget
// refusal is the library's own ErrBudgetExhausted — and remembers every enclave
// it handed out, so a test can prove each one was destroyed.
type recordingAllocator struct {
	alloc *enclave.Allocator

	mu      sync.Mutex
	created []*enclave.MemoryEnclave
}

// newRecordingAllocator returns an allocator whose budget holds exactly pages
// small cache entries; each entry occupies one page.
func newRecordingAllocator(t *testing.T, pages int64) *recordingAllocator {
	t.Helper()
	alloc, err := enclave.NewAllocator(pages * enclave.LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	return &recordingAllocator{alloc: alloc}
}

func (r *recordingAllocator) New(data []byte) (*enclave.MemoryEnclave, error) {
	e, err := r.alloc.New(data)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.created = append(r.created, e)
	r.mu.Unlock()
	return e, nil
}

func (r *recordingAllocator) alive() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.created {
		if e.IsAlive() {
			n++
		}
	}
	return n
}

func (r *recordingAllocator) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.created)
}

// newBudgetedUserInfoClient returns a UserInfo client whose cache allocates from
// alloc and reads time from clock.
func newBudgetedUserInfoClient(alloc *recordingAllocator, clock *fakeClock, userInfoURL string) *userInfoClient {
	return newBudgetedUserInfoClientSized(alloc, clock, userInfoURL, 10)
}

// newBudgetedUserInfoClientSized is newBudgetedUserInfoClient with a cache
// bounded to maxSize entries.
func newBudgetedUserInfoClientSized(alloc *recordingAllocator, clock *fakeClock, userInfoURL string, maxSize int) *userInfoClient {
	config := &Config{
		Provider: &mockUserInfoProvider{userInfoURL: userInfoURL},
		OIDC: &OIDCConfig{
			Enabled:  true,
			UserInfo: UserInfoConfig{Enabled: true, CacheTTL: time.Minute, CacheMaxSize: maxSize},
		},
	}
	client := newUserInfoClient(http.DefaultClient, config, nil)
	client.cache = newSealedLRU(maxSize, alloc.New, clock.Now)
	return client
}

func TestUserInfoCacheReclaimsExpiredEntriesBeforeAllocating(t *testing.T) {
	alloc := newRecordingAllocator(t, 2)
	clock := newFakeClock()
	client := newBudgetedUserInfoClient(alloc, clock, "")

	mustCacheUserInfo(t, client, "a", &UserInfo{Subject: "a"})
	mustCacheUserInfo(t, client, "b", &UserInfo{Subject: "b"})
	first, second := userInfoSealed(client, "a"), userInfoSealed(client, "b")

	if avail := alloc.alloc.Available(); avail != 0 {
		t.Fatalf("budget has %d bytes free, want it full", avail)
	}

	// Once both have expired, the next insert has to succeed: the dead entries
	// are reclaimed before the new one is allocated, not after.
	clock.Advance(2 * time.Minute)
	mustCacheUserInfo(t, client, "c", &UserInfo{Subject: "c"})

	if first.IsAlive() || second.IsAlive() {
		t.Error("expired UserInfo entries are still alive after the insert that needed their budget")
	}
	if userInfoSealed(client, "a") != nil {
		t.Error("expired entry a is still in the cache")
	}
	if cached := client.getFromCache("c"); cached == nil || cached.Subject != "c" {
		t.Errorf("getFromCache(c) = %+v, want the new entry", cached)
	}
}

func TestUserInfoCacheReadDestroysAnExpiredEntry(t *testing.T) {
	alloc := newRecordingAllocator(t, 2)
	clock := newFakeClock()
	client := newBudgetedUserInfoClient(alloc, clock, "")

	mustCacheUserInfo(t, client, "a", &UserInfo{Subject: "a"})
	sealed := userInfoSealed(client, "a")

	clock.Advance(2 * time.Minute)

	if cached := client.getFromCache("a"); cached != nil {
		t.Errorf("getFromCache() of an expired entry = %+v, want nil", cached)
	}
	if sealed.IsAlive() {
		t.Error("a read that found an expired entry left its enclave alive")
	}
	if userInfoSealed(client, "a") != nil {
		t.Error("a read that found an expired entry left it in the cache")
	}
}

func TestUserInfoCacheRefusesInsertsAfterClose(t *testing.T) {
	alloc := newRecordingAllocator(t, 4)
	client := newBudgetedUserInfoClient(alloc, newFakeClock(), "")

	mustCacheUserInfo(t, client, "a", &UserInfo{Subject: "a"})
	client.Close()
	client.Close() // idempotent

	if alloc.alive() != 0 {
		t.Error("Close left a cached UserInfo enclave alive")
	}
	if err := client.cacheUserInfo("b", &UserInfo{Subject: "b"}); !errors.Is(err, ErrCacheClosed) {
		t.Errorf("cacheUserInfo() after Close = %v, want ErrCacheClosed", err)
	}
	if userInfoLen(client) != 0 || alloc.alive() != 0 {
		t.Error("a closed UserInfo cache holds a live entry")
	}
}

// TestUserInfoInFlightDuringCloseCannotOutliveIt is the shutdown race: a
// GetUserInfo whose HTTP request is in flight when the Authenticator closes must
// not insert a fresh enclave after Close cleared the cache.
func TestUserInfoInFlightDuringCloseCannotOutliveIt(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": "user-1"})
	}))
	defer server.Close()

	alloc := newRecordingAllocator(t, 4)
	client := newBudgetedUserInfoClient(alloc, newFakeClock(), server.URL)
	auth := &Authenticator{config: client.config, cache: &noopCache{}, userInfoClient: client}

	type result struct {
		info *UserInfo
		err  error
	}
	done := make(chan result, 1)
	go func() {
		info, err := client.GetUserInfo(context.Background(), sealedForTest(t, "access"), "https://issuer.example")
		done <- result{info, err}
	}()

	<-entered
	if err := auth.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	close(release)
	res := <-done

	if !errors.Is(res.err, ErrCacheClosed) {
		t.Errorf("GetUserInfo() racing Close = %v, %v; want ErrCacheClosed", res.info, res.err)
	}
	entries := userInfoLen(client)
	if entries != 0 {
		t.Errorf("the UserInfo cache holds %d entries after Close", entries)
	}
	if alloc.alive() != 0 {
		t.Errorf("%d UserInfo enclaves survived Close", alloc.alive())
	}
}

// newBudgetedLRUCache returns an LRU cache that allocates from alloc and reads
// time from clock.
func newBudgetedLRUCache(alloc *recordingAllocator, clock *fakeClock) *lruCache {
	return newLRUCacheWith(10, alloc.New, clock.Now)
}

func TestLRUCacheReclaimsExpiredEntriesBeforeAllocating(t *testing.T) {
	alloc := newRecordingAllocator(t, 2)
	clock := newFakeClock()
	cache := newBudgetedLRUCache(alloc, clock)
	defer cache.Close()

	mustSet(t, cache, "a", &TokenClaims{Subject: "a"}, time.Minute)
	mustSet(t, cache, "b", &TokenClaims{Subject: "b"}, time.Minute)
	first, second := sealedEntry(cache, "a"), sealedEntry(cache, "b")

	if avail := alloc.alloc.Available(); avail != 0 {
		t.Fatalf("budget has %d bytes free, want it full", avail)
	}

	clock.Advance(2 * time.Minute)
	mustSet(t, cache, "c", &TokenClaims{Subject: "c"}, time.Minute)

	if first.IsAlive() || second.IsAlive() {
		t.Error("expired claims entries are still alive after the insert that needed their budget")
	}
	if got := cache.Get("c"); got == nil || got.Subject != "c" {
		t.Errorf("Get(c) = %+v, want the new entry", got)
	}
}

func TestLRUCacheRefusesInsertsAfterClose(t *testing.T) {
	alloc := newRecordingAllocator(t, 4)
	cache := newBudgetedLRUCache(alloc, newFakeClock())

	mustSet(t, cache, "a", &TokenClaims{Subject: "a"}, time.Minute)
	cache.Close()

	before := alloc.count()
	if err := cache.Set("b", &TokenClaims{Subject: "b"}, time.Minute); !errors.Is(err, ErrCacheClosed) {
		t.Errorf("Set() after Close = %v, want ErrCacheClosed", err)
	}
	if alloc.count() != before {
		t.Error("a closed cache allocated locked memory for an entry it cannot keep")
	}
	if alloc.alive() != 0 || sealedEntry(cache, "b") != nil {
		t.Error("a closed claims cache holds a live entry")
	}
}

// TestLRUCacheEvictsForCapacityBeforeAllocating is the at-capacity case: the
// cache is at maxSize and its live entries fill the locked-memory budget. The
// capacity eviction has to happen before the new entry is allocated, or the
// allocation is refused and ValidateToken rejects a valid token.
func TestLRUCacheEvictsForCapacityBeforeAllocating(t *testing.T) {
	alloc := newRecordingAllocator(t, 2)
	cache := newLRUCacheWith(2, alloc.New, newFakeClock().Now)
	defer cache.Close()

	mustSet(t, cache, "a", &TokenClaims{Subject: "a"}, time.Minute)
	mustSet(t, cache, "b", &TokenClaims{Subject: "b"}, time.Minute)
	oldest, newer := sealedEntry(cache, "a"), sealedEntry(cache, "b")

	mustSet(t, cache, "c", &TokenClaims{Subject: "c"}, time.Minute)

	if oldest.IsAlive() {
		t.Error("the evicted LRU entry's enclave is still alive")
	}
	if !newer.IsAlive() || cache.Get("b") == nil {
		t.Error("capacity eviction removed more than the LRU entry")
	}
	if got := cache.Get("c"); got == nil || got.Subject != "c" {
		t.Errorf("Get(c) = %+v, want the new entry", got)
	}
}

// TestLRUCacheEvictsOnceWhenTheBudgetRefuses covers a budget smaller than
// maxSize: the cache is under capacity, but live entries fill the allowance.
// The cache evicts its LRU entry and retries the allocation once.
func TestLRUCacheEvictsOnceWhenTheBudgetRefuses(t *testing.T) {
	alloc := newRecordingAllocator(t, 2)
	cache := newLRUCacheWith(10, alloc.New, newFakeClock().Now)
	defer cache.Close()

	mustSet(t, cache, "a", &TokenClaims{Subject: "a"}, time.Minute)
	mustSet(t, cache, "b", &TokenClaims{Subject: "b"}, time.Minute)
	oldest, newer := sealedEntry(cache, "a"), sealedEntry(cache, "b")

	mustSet(t, cache, "c", &TokenClaims{Subject: "c"}, time.Minute)

	if oldest.IsAlive() {
		t.Error("the entry evicted to make room in the budget is still alive")
	}
	if !newer.IsAlive() || cache.Get("b") == nil {
		t.Error("the budget retry evicted more than one entry")
	}
	if got := cache.Get("c"); got == nil || got.Subject != "c" {
		t.Errorf("Get(c) = %+v, want the new entry", got)
	}
}

// TestLRUCacheFailsClosedWhenTheRetryIsRefused bounds the retry: an entry the
// budget cannot hold, even after one eviction, is refused with the allocator's
// error. Nothing is stored, and nothing falls back to ordinary memory.
func TestLRUCacheFailsClosedWhenTheRetryIsRefused(t *testing.T) {
	alloc := newRecordingAllocator(t, 1)
	cache := newLRUCacheWith(10, alloc.New, newFakeClock().Now)
	defer cache.Close()

	mustSet(t, cache, "a", &TokenClaims{Subject: "a"}, time.Minute)

	// Larger than one page once encoded, so no eviction can make room.
	huge := &TokenClaims{Subject: "huge", Name: strings.Repeat("x", int(enclave.LockedSize(1))+1)}
	if err := cache.Set("huge", huge, time.Minute); !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("Set() of an entry the budget cannot hold = %v, want ErrBudgetExhausted", err)
	}
	if sealedEntry(cache, "huge") != nil {
		t.Error("a refused entry was stored")
	}
	if alloc.alive() != 0 {
		t.Errorf("%d enclaves are alive; the bounded retry evicted one entry and should have left none", alloc.alive())
	}
}

// The UserInfo cache is bounded exactly like the claims cache: an unbounded
// cache of locked pages is a memory-exhaustion path for anyone who can present
// distinct access tokens.

func TestUserInfoCacheIsBoundedByCacheMaxSize(t *testing.T) {
	alloc := newRecordingAllocator(t, 2)
	client := newBudgetedUserInfoClientSized(alloc, newFakeClock(), "", 2)

	mustCacheUserInfo(t, client, "a", &UserInfo{Subject: "a"})
	mustCacheUserInfo(t, client, "b", &UserInfo{Subject: "b"})
	oldest := userInfoSealed(client, "a")

	// At capacity, with live entries filling the budget, a new key still goes
	// in: the LRU entry is evicted before the allocation, not after.
	mustCacheUserInfo(t, client, "c", &UserInfo{Subject: "c"})

	if oldest.IsAlive() {
		t.Error("the evicted UserInfo entry's enclave is still alive")
	}
	if n := userInfoLen(client); n != 2 {
		t.Errorf("UserInfo cache holds %d entries, want its CacheMaxSize of 2", n)
	}
	if client.getFromCache("b") == nil || client.getFromCache("c") == nil {
		t.Error("capacity eviction removed more than the LRU entry")
	}
}

func TestUserInfoCacheEvictsLeastRecentlyUsed(t *testing.T) {
	alloc := newRecordingAllocator(t, 4)
	client := newBudgetedUserInfoClientSized(alloc, newFakeClock(), "", 2)

	mustCacheUserInfo(t, client, "a", &UserInfo{Subject: "a"})
	mustCacheUserInfo(t, client, "b", &UserInfo{Subject: "b"})
	if client.getFromCache("a") == nil { // a is now the most recently used
		t.Fatal("getFromCache(a) missed")
	}
	untouched := userInfoSealed(client, "b")

	mustCacheUserInfo(t, client, "c", &UserInfo{Subject: "c"})

	if untouched.IsAlive() || client.getFromCache("b") != nil {
		t.Error("the least recently used entry (b) was not the one evicted")
	}
	if client.getFromCache("a") == nil {
		t.Error("a recently read entry was evicted")
	}
}

func TestUserInfoCacheEvictsOnceWhenTheBudgetRefuses(t *testing.T) {
	alloc := newRecordingAllocator(t, 2)
	client := newBudgetedUserInfoClientSized(alloc, newFakeClock(), "", 10)

	mustCacheUserInfo(t, client, "a", &UserInfo{Subject: "a"})
	mustCacheUserInfo(t, client, "b", &UserInfo{Subject: "b"})
	oldest, newer := userInfoSealed(client, "a"), userInfoSealed(client, "b")

	mustCacheUserInfo(t, client, "c", &UserInfo{Subject: "c"})

	if oldest.IsAlive() {
		t.Error("the entry evicted to make room in the budget is still alive")
	}
	if !newer.IsAlive() {
		t.Error("the budget retry evicted more than one entry")
	}
}

func TestUserInfoCacheFailsClosedWhenTheRetryIsRefused(t *testing.T) {
	alloc := newRecordingAllocator(t, 1)
	client := newBudgetedUserInfoClientSized(alloc, newFakeClock(), "", 10)

	mustCacheUserInfo(t, client, "a", &UserInfo{Subject: "a"})

	huge := &UserInfo{Subject: "huge", Name: strings.Repeat("x", int(enclave.LockedSize(1))+1)}
	if err := client.cacheUserInfo("huge", huge); !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("cacheUserInfo() of an entry the budget cannot hold = %v, want ErrBudgetExhausted", err)
	}
	if userInfoSealed(client, "huge") != nil || alloc.alive() != 0 {
		t.Error("a refused UserInfo entry was stored, or the retry left an enclave alive")
	}
}

func TestUserInfoCacheMaxSizeDefault(t *testing.T) {
	if got := DefaultOIDCConfig().UserInfo.CacheMaxSize; got != 1000 {
		t.Errorf("DefaultOIDCConfig().UserInfo.CacheMaxSize = %d, want 1000", got)
	}

	config := &Config{
		Provider: newTestProvider("https://idp.example/auth", "https://idp.example/token"),
		ClientID: "client",
		Flow:     FlowTokenValidation,
		Validation: TokenValidationConfig{
			Method:  ValidationJWT,
			JWKSURL: "https://idp.example/jwks",
		},
		OIDC: &OIDCConfig{Enabled: true, SkipDiscovery: true, Discovery: &OIDCDiscoveryConfig{}},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}
	if got := config.OIDC.UserInfo.CacheMaxSize; got != 1000 {
		t.Errorf("Validate() left UserInfo.CacheMaxSize = %d, want the default 1000", got)
	}
}

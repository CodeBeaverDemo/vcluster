package oauth2

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "net/url"
    "sync"
    "testing"
    "time"
    "io"
    "strings"
    "errors"
)

// mockTokenResponse is a helper that returns a JSON token response
func mockTokenResponse(t *testing.T, accessToken, refreshToken string, expiresIn int) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
    token := map[string]interface{}{
    "access_token":  accessToken,
    "token_type":    "bearer",
    "refresh_token": refreshToken,
    "expires_in":    expiresIn,
    }
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(token); err != nil {
    t.Fatalf("failed to encode token: %v", err)
    }
    }
}

// TestAuthCodeURL tests that the AuthCodeURL method correctly builds the URL
func TestAuthCodeURL(t *testing.T) {
    cfg := &Config{
    ClientID:    "testclient",
    RedirectURL: "http://localhost/callback",
    Scopes:      []string{"scope1", "scope2"},
    Endpoint: Endpoint{
    AuthURL: "http://auth.example.com/auth",
    },
    }
    state := "abc123"
    // Generate the authorization URL with an extra custom parameter.
    authURL := cfg.AuthCodeURL(state, SetAuthURLParam("custom", "value"))
    parsed, err := url.Parse(authURL)
    if err != nil {
    t.Fatalf("failed to parse auth URL: %v", err)
    }
    q := parsed.Query()
    if q.Get("response_type") != "code" {
    t.Errorf("expected response_type=code, got %s", q.Get("response_type"))
    }
    if q.Get("client_id") != "testclient" {
    t.Errorf("expected client_id=testclient, got %s", q.Get("client_id"))
    }
    if q.Get("redirect_uri") != "http://localhost/callback" {
    t.Errorf("expected redirect_uri match, got %s", q.Get("redirect_uri"))
    }
    if q.Get("scope") != "scope1 scope2" {
    t.Errorf("expected scope 'scope1 scope2', got %s", q.Get("scope"))
    }
    if q.Get("state") != state {
    t.Errorf("expected state '%s', got %s", state, q.Get("state"))
    }
    if q.Get("custom") != "value" {
    t.Errorf("expected custom=value, got %s", q.Get("custom"))
    }
}

// TestPasswordCredentialsToken tests the PasswordCredentialsToken method.
func TestPasswordCredentialsToken(t *testing.T) {
    ts := httptest.NewServer(mockTokenResponse(t, "pass_token", "pass_refresh", 3600))
    defer ts.Close()

    cfg := &Config{
    ClientID:     "testclient",
    ClientSecret: "secret",
    Endpoint: Endpoint{
    TokenURL: ts.URL,
    },
    Scopes: []string{"scope1"},
    }
    // Override the HTTPClient via context.
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    token, err := cfg.PasswordCredentialsToken(ctx, "user", "pass")
    if err != nil {
    t.Fatalf("expected no error, got %v", err)
    }
    if token.AccessToken != "pass_token" {
    t.Errorf("expected access_token 'pass_token', got %s", token.AccessToken)
    }
    if token.RefreshToken != "pass_refresh" {
    t.Errorf("expected refresh_token 'pass_refresh', got %s", token.RefreshToken)
    }
}

// TestExchange tests the Exchange method which converts an authorization code to a token.
func TestExchange(t *testing.T) {
    ts := httptest.NewServer(mockTokenResponse(t, "ex_token", "ex_refresh", 3600))
    defer ts.Close()

    cfg := &Config{
    ClientID:     "testclient",
    ClientSecret: "secret",
    RedirectURL:  "http://localhost/callback",
    Endpoint: Endpoint{
    TokenURL: ts.URL,
    AuthURL:  "http://auth.example.com/auth",
    },
    Scopes: []string{"scope1"},
    }
    // Override the HTTPClient via context.
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    token, err := cfg.Exchange(ctx, "authcode", SetAuthURLParam("custom", "value"))
    if err != nil {
    t.Fatalf("Exchange failed: %v", err)
    }
    if token.AccessToken != "ex_token" {
    t.Errorf("expected access_token 'ex_token', got %s", token.AccessToken)
    }
}

// TestTokenSourceReuse checks that a TokenSource properly reuses an unexpired token and refreshes it when expired.
func TestTokenSourceReuse(t *testing.T) {
    // Create an expired token.
    expiredToken := &Token{
    AccessToken:  "old",
    RefreshToken: "refresh1",
    Expiry:       time.Now().Add(-10 * time.Minute),
    }

    // Create a test server that returns a new token.
    callCount := 0
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    callCount++
    mockToken := map[string]interface{}{
    "access_token":  "new",
    "token_type":    "bearer",
    "refresh_token": "refresh2",
    "expires_in":    3600,
    }
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(mockToken); err != nil {
    t.Fatalf("failed to encode token: %v", err)
    }
    }))
    defer ts.Close()

    cfg := &Config{
    ClientID:     "testclient",
    ClientSecret: "secret",
    Endpoint: Endpoint{
    TokenURL: ts.URL,
    },
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    tsrc := cfg.TokenSource(ctx, expiredToken)
    // First call should refresh the token.
    token1, err := tsrc.Token()
    if err != nil {
    t.Fatalf("Token() failed: %v", err)
    }
    if token1.AccessToken != "new" {
    t.Errorf("expected new access token, got %s", token1.AccessToken)
    }
    if token1.RefreshToken != "refresh2" {
    t.Errorf("expected new refresh token, got %s", token1.RefreshToken)
    }
    // Second call should return the same token as it is not expired.
    token2, err := tsrc.Token()
    if err != nil {
    t.Fatalf("Token() second call failed: %v", err)
    }
    if token2 != token1 {
    t.Errorf("expected token reuse, got different tokens")
    }
    if callCount != 1 {
    t.Errorf("expected 1 refresh call, got %d", callCount)
    }
}

// TestStaticTokenSource verifies that StaticTokenSource always returns the given token.
func TestStaticTokenSource(t *testing.T) {
    tok := &Token{
    AccessToken: "static",
    }
    tsrc := StaticTokenSource(tok)
    token, err := tsrc.Token()
    if err != nil {
    t.Fatalf("StaticTokenSource failed: %v", err)
    }
    if token != tok {
    t.Errorf("expected same token, got different")
    }
}

// TestReuseTokenSourceWithExpiry tests the token reuse behavior with an expiry buffer.
func TestReuseTokenSourceWithExpiry(t *testing.T) {
    // Create an expired token with a custom expiry delta.
    expiredToken := &Token{
    AccessToken:  "expired",
    RefreshToken: "refresh",
    Expiry:       time.Now().Add(-5 * time.Minute),
    }

    ts := httptest.NewServer(mockTokenResponse(t, "renewed", "refreshNew", 3600))
    defer ts.Close()

    cfg := &Config{
    ClientID:     "testclient",
    ClientSecret: "secret",
    Endpoint: Endpoint{
    TokenURL: ts.URL,
    },
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    // Wrap the token source with an expiry buffer of 1 minute.
    newSrc := ReuseTokenSourceWithExpiry(expiredToken, cfg.TokenSource(ctx, expiredToken), 1*time.Minute)
    tok, err := newSrc.Token()
    if err != nil {
    t.Fatalf("Token retrieval failed: %v", err)
    }
    if tok.AccessToken != "renewed" {
    t.Errorf("expected renewed token, got %s", tok.AccessToken)
    }
}

// TestTokenRefreshWithoutRefreshToken ensures that requesting a token with no refresh token errors.
func TestTokenRefreshWithoutRefreshToken(t *testing.T) {
    emptyToken := &Token{
    AccessToken: "no_refresh",
    Expiry:      time.Now().Add(-10 * time.Minute),
    }
    cfg := &Config{
    ClientID:     "testclient",
    ClientSecret: "secret",
    Endpoint: Endpoint{
    TokenURL: "http://invalid", // this URL is never used because refreshToken is empty
    },
    }
    ctx := context.Background()
    tsrc := cfg.TokenSource(ctx, emptyToken)
    _, err := tsrc.Token()
    if err == nil {
    t.Errorf("expected error when no refresh token is set")
    }
}
// TestNewClientNilTokenSource tests that NewClient returns a non-nil client when TokenSource is nil.
func TestNewClientNilTokenSource(t *testing.T) {
    ctx := context.Background()
    client := NewClient(ctx, nil)
    if client == nil {
        t.Errorf("expected non-nil client")
    }
}

// TestRegisterBrokenAuthHeaderProvider ensures that calling RegisterBrokenAuthHeaderProvider does not cause a panic.
func TestRegisterBrokenAuthHeaderProvider(t *testing.T) {
    // This function is a no-op, so simply calling it should not lead to any issues.
    RegisterBrokenAuthHeaderProvider("dummy")
}

// TestTokenSourceValid tests that a valid (non-expired) Token is reused without refreshing.
func TestTokenSourceValid(t *testing.T) {
    validToken := &Token{
        AccessToken: "valid",
        Expiry:      time.Now().Add(10 * time.Minute),
    }
    cfg := &Config{
        ClientID:     "testclient",
        ClientSecret: "secret",
        Endpoint: Endpoint{
            TokenURL: "http://invalid", // not used because the token is valid
        },
    }
    ctx := context.Background()
    tsrc := cfg.TokenSource(ctx, validToken)
    tok, err := tsrc.Token()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if tok != validToken {
        t.Errorf("expected to receive the same valid token")
    }
}

// TestReuseTokenSourceNilToken tests that ReuseTokenSource works correctly when the initial token is nil.
func TestReuseTokenSourceNilToken(t *testing.T) {
    staticToken := &Token{
        AccessToken: "static-nil",
        Expiry:      time.Now().Add(10 * time.Minute),
    }
    tsrc := ReuseTokenSource(nil, StaticTokenSource(staticToken))
    tok, err := tsrc.Token()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if tok.AccessToken != "static-nil" {
        t.Errorf("expected static token from reuse source, got %s", tok.AccessToken)
    }
}

// TestNewClientAddsAuthHeader tests that the HTTP client returned by NewClient adds the correct Authorization header.
func TestNewClientAddsAuthHeader(t *testing.T) {
    staticToken := &Token{
        AccessToken: "testtoken",
        Expiry:      time.Now().Add(10 * time.Minute),
    }
    var capturedAuth string
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        capturedAuth = r.Header.Get("Authorization")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("ok"))
    }))
    defer ts.Close()

    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    client := NewClient(ctx, StaticTokenSource(staticToken))
    resp, err := client.Get(ts.URL)
    if err != nil {
        t.Fatalf("request failed: %v", err)
    }
    resp.Body.Close()
    expectedAuth := "Bearer testtoken"
    if capturedAuth != expectedAuth {
        t.Errorf("expected Authorization header %q, got %q", expectedAuth, capturedAuth)
    }
}
// TestNoContextEquality tests that NoContext equals context.TODO()
func TestNoContextEquality(t *testing.T) {
    if NoContext != context.TODO() {
        t.Error("expected NoContext to equal context.TODO()")
    }
}

// TestExchangeBadJSON tests that Exchange returns an error when the token response contains invalid JSON.
func TestExchangeBadJSON(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte("invalid json"))
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "testclient",
        ClientSecret: "secret",
        RedirectURL:  "http://localhost/callback",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
            AuthURL:  "http://auth.example.com/auth",
        },
        Scopes: []string{"scope1"},
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    _, err := cfg.Exchange(ctx, "authcode")
    if err == nil {
        t.Error("expected error due to bad JSON response, got nil")
    }
}

// TestPasswordCredentialsTokenBadJSON tests that PasswordCredentialsToken returns an error when the token response contains invalid JSON.
func TestPasswordCredentialsTokenBadJSON(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte("not json"))
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "testclient",
        ClientSecret: "secret",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
        },
        Scopes: []string{"scope1"},
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    _, err := cfg.PasswordCredentialsToken(ctx, "user", "pass")
    if err == nil {
        t.Error("expected error due to invalid JSON, got nil")
    }
}

// TestReuseTokenSourceDoubleWrap tests that ReuseTokenSource does not wrap an already reused token source.
func TestReuseTokenSourceDoubleWrap(t *testing.T) {
    staticToken := &Token{
        AccessToken: "double",
        Expiry:      time.Now().Add(10 * time.Minute),
    }
    baseTS := StaticTokenSource(staticToken)
    // First wrap the static token source
    rts1 := ReuseTokenSource(nil, baseTS)
    // Second wrap should not perform an extra mutex operation
    rts2 := ReuseTokenSource(nil, rts1)
    tok, err := rts2.Token()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if tok.AccessToken != "double" {
        t.Errorf("expected token access token 'double', got %s", tok.AccessToken)
    }
}
// TestReuseTokenSourceConcurrency tests that concurrent calls to a reused TokenSource
// only trigger a single refresh call, and that all goroutines receive the same token instance.
func TestReuseTokenSourceConcurrency(t *testing.T) {
    // Create an expired token.
    expiredToken := &Token{
        AccessToken:  "expired",
        RefreshToken: "refresh",
        Expiry:       time.Now().Add(-5 * time.Minute),
    }

    callCount := 0
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        callCount++
        tokenData := map[string]interface{}{
            "access_token":  "new_concurrent",
            "token_type":    "bearer",
            "refresh_token": "refresh_concurrent",
            "expires_in":    3600,
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(tokenData)
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "concurrent",
        ClientSecret: "secret",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
        },
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    tsrc := cfg.TokenSource(ctx, expiredToken)

    const n = 10
    var wg sync.WaitGroup
    tokens := make(chan *Token, n)
    for i := 0; i < n; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            tok, err := tsrc.Token()
            if err != nil {
                t.Errorf("unexpected error: %v", err)
            }
            tokens <- tok
        }()
    }
    wg.Wait()
    close(tokens)

    var first *Token
    for tok := range tokens {
        if first == nil {
            first = tok
        } else if tok != first {
            t.Errorf("expected same token instance, got different tokens")
        }
    }
    if callCount != 1 {
        t.Errorf("expected refresh call count 1, got %d", callCount)
    }
}

// TestAuthCodeURLNoRedirect tests that AuthCodeURL omits the redirect_uri query parameter when not set.
func TestAuthCodeURLNoRedirect(t *testing.T) {
    cfg := &Config{
        ClientID: "noredirect",
        Scopes:   []string{"scopeA", "scopeB"},
        Endpoint: Endpoint{
            AuthURL: "http://auth.example.com/login",
        },
    }
    state := "state123"
    authURL := cfg.AuthCodeURL(state)
    parsed, err := url.Parse(authURL)
    if err != nil {
        t.Fatalf("failed to parse URL: %v", err)
    }
    q := parsed.Query()
    if q.Get("redirect_uri") != "" {
        t.Errorf("expected no redirect_uri, got %s", q.Get("redirect_uri"))
    }
    if q.Get("response_type") != "code" {
        t.Errorf("expected response_type 'code', got %s", q.Get("response_type"))
    }
    if q.Get("client_id") != "noredirect" {
        t.Errorf("expected client_id 'noredirect', got %s", q.Get("client_id"))
    }
}
// TestAuthCodeURLWithExistingQuery tests that AuthCodeURL correctly appends options
// when the AuthURL already has existing query parameters.
func TestAuthCodeURLWithExistingQuery(t *testing.T) {
    cfg := &Config{
        ClientID:    "clientQuery",
        RedirectURL: "http://localhost/redirect",
        Scopes:      []string{"queryscope"},
        Endpoint: Endpoint{
            AuthURL: "http://auth.example.com/auth?existing=param",
        },
    }
    authURL := cfg.AuthCodeURL("stateQuery", SetAuthURLParam("newParam", "newValue"))
    parsed, err := url.Parse(authURL)
    if err != nil {
        t.Fatalf("failed to parse auth URL: %v", err)
    }
    q := parsed.Query()
    if q.Get("existing") != "param" {
        t.Errorf("expected existing=param, got %s", q.Get("existing"))
    }
    if q.Get("newParam") != "newValue" {
        t.Errorf("expected newParam=newValue, got %s", q.Get("newParam"))
    }
    if q.Get("client_id") != "clientQuery" {
        t.Errorf("expected client_id=clientQuery, got %s", q.Get("client_id"))
    }
}

// TestExchangeServerError tests that Exchange returns an error when the token server responds with an HTTP error.
func TestExchangeServerError(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        http.Error(w, "server error", http.StatusInternalServerError)
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "errorClient",
        ClientSecret: "errorSecret",
        RedirectURL:  "http://localhost/callback",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
            AuthURL:  "http://auth.example.com/auth",
        },
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    _, err := cfg.Exchange(ctx, "errorcode")
    if err == nil {
        t.Error("expected error from Exchange due to server error, got nil")
    }
}

// TestPasswordCredentialsTokenServerError tests that PasswordCredentialsToken returns an error
// when the token endpoint responds with an error.
func TestPasswordCredentialsTokenServerError(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        http.Error(w, "server error", http.StatusInternalServerError)
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "errorClient",
        ClientSecret: "errorSecret",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
        },
        Scopes: []string{"errscope"},
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    _, err := cfg.PasswordCredentialsToken(ctx, "user", "pass")
    if err == nil {
        t.Error("expected error from PasswordCredentialsToken due to server error, got nil")
    }
}

// TestTokenSourceRefreshError tests that a TokenSource properly returns an error
// when the refresh token request fails with an HTTP error.
func TestTokenSourceRefreshError(t *testing.T) {
    // Create an expired token with a refresh token.
    expiredToken := &Token{
        AccessToken:  "expired",
        RefreshToken: "bad_refresh",
        Expiry:       time.Now().Add(-2 * time.Minute),
    }

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        http.Error(w, "refresh error", http.StatusInternalServerError)
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "client",
        ClientSecret: "secret",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
        },
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    tsrc := cfg.TokenSource(ctx, expiredToken)
    _, err := tsrc.Token()
    if err == nil {
        t.Error("expected error when refresh token request fails, got nil")
    }
}
func TestTokenValidity(t *testing.T) {
    // Test that the Valid method on a Token returns the expected result.
    now := time.Now()
    validToken := &Token{
        AccessToken: "valid",
        Expiry:      now.Add(10 * time.Minute),
    }
    if !validToken.Valid() {
        t.Error("expected token to be valid")
    }

    expiredToken := &Token{
        AccessToken: "expired",
        Expiry:      now.Add(-10 * time.Minute),
    }
    if expiredToken.Valid() {
        t.Error("expected token to be invalid")
    }

    // A token with zero expiry time should be considered valid.
    zeroExpiryToken := &Token{
        AccessToken: "zero",
    }
    if !zeroExpiryToken.Valid() {
        t.Error("expected token with zero expiry to be valid")
    }
}

func TestCustomRoundTripper(t *testing.T) {
    // Test that NewClient uses a custom HTTP client's transport when one is provided via the context.
    called := false
    customRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
        called = true
        return &http.Response{
            StatusCode: http.StatusOK,
            Body:       io.NopCloser(strings.NewReader("ok")),
        }, nil
    })
    customClient := &http.Client{Transport: customRT}
    ctx := context.WithValue(context.Background(), HTTPClient, customClient)
    staticToken := &Token{
        AccessToken: "custom",
        Expiry:      time.Now().Add(10 * time.Minute),
    }
    client := NewClient(ctx, StaticTokenSource(staticToken))
    resp, err := client.Get("http://example.com")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    resp.Body.Close()
    if !called {
        t.Error("expected custom RoundTripper to be called")
    }
}
// TestTokenRefresherNoRefreshToken tests that tokenRefresher returns an error when no refresh token is set.
func TestTokenRefresherNoRefreshToken(t *testing.T) {
    tr := &tokenRefresher{
        ctx:          context.Background(),
        conf:         &Config{},
        refreshToken: "",
    }
    _, err := tr.Token()
    if err == nil || !strings.Contains(err.Error(), "refresh token is not set") {
        t.Errorf("expected error about missing refresh token, got %v", err)
    }
}
// TestTokenRefresherUpdatesRefreshToken verifies that tokenRefresher updates its refreshToken field when a refresh occurs.
func TestTokenRefresherUpdatesRefreshToken(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenResp := map[string]interface{}{
            "access_token":  "updated_access",
            "token_type":    "bearer",
            "refresh_token": "updated_refresh",
            "expires_in":    3600,
        }
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(tokenResp); err != nil {
            t.Fatalf("failed to encode token: %v", err)
        }
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "dummy",
        ClientSecret: "dummy",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
        },
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())

    // Create a tokenRefresher with an initial refreshToken "old_refresh"
    tr := &tokenRefresher{
        ctx:          ctx,
        conf:         cfg,
        refreshToken: "old_refresh",
    }

    token, err := tr.Token()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if token.AccessToken != "updated_access" {
        t.Errorf("expected access_token 'updated_access', got %s", token.AccessToken)
    }
    if token.RefreshToken != "updated_refresh" {
        t.Errorf("expected refresh_token 'updated_refresh', got %s", token.RefreshToken)
    }
    if tr.refreshToken != "updated_refresh" {
        t.Errorf("expected tokenRefresher.refreshToken to be updated to 'updated_refresh', got %s", tr.refreshToken)
    }
}

// TestSetAuthURLParam verifies that SetAuthURLParam correctly sets URL parameters.
func TestSetAuthURLParam(t *testing.T) {
    values := url.Values{}
    opt := SetAuthURLParam("key", "value")
    opt.setValue(values)
    if values.Get("key") != "value" {
        t.Errorf("expected 'key' parameter to be 'value', got %s", values.Get("key"))
    }
}

// errorSource is a TokenSource that always returns an error.
type errorSource struct{}

func (e *errorSource) Token() (*Token, error) {
    return nil, errors.New("token source error")
}

// TestReuseTokenSourceWithExpiryNilToken tests that ReuseTokenSourceWithExpiry correctly uses a nil initial token.
// It wraps a static token source and verifies that the expiry buffer is applied.
func TestReuseTokenSourceWithExpiryNilToken(t *testing.T) {
    expectedToken := &Token{
        AccessToken: "expirynil",
        Expiry:      time.Now().Add(10 * time.Minute),
    }
    tsrc := StaticTokenSource(expectedToken)
    newSrc := ReuseTokenSourceWithExpiry(nil, tsrc, 30*time.Second)
    tok, err := newSrc.Token()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if tok != expectedToken {
        t.Errorf("expected to receive same token instance")
    }
    if tok.expiryDelta != 30*time.Second {
        t.Errorf("expected expiryDelta 30s, got %v", tok.expiryDelta)
    }
}

// TestNewClientTokenSourceError tests that if a TokenSource returns an error,
// NewClient's underlying transport propagates that error when making a request.
func TestNewClientTokenSourceError(t *testing.T) {
    errSrc := &errorSource{}
    ctx := context.Background()
    client := NewClient(ctx, errSrc)
    // Make a request to an example URL.
    _, err := client.Get("http://example.com")
    if err == nil {
        t.Errorf("expected error from token source, got nil")
    }
}
// TestReuseTokenSourceEarlyExpiryNearExpiry tests that a token which isn’t expired in absolute terms
// but is near expiry as defined by the early expiry buffer is automatically refreshed.
func TestReuseTokenSourceEarlyExpiryNearExpiry(t *testing.T) {
    // Create a token that expires in 30 seconds.
    nearExpiryToken := &Token{
        AccessToken:  "near",
        RefreshToken: "refresh_earl",
        Expiry:       time.Now().Add(30 * time.Second),
    }
    callCount := 0
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        callCount++
        tokenData := map[string]interface{}{
            "access_token":  "renewed_early",
            "token_type":    "bearer",
            "refresh_token": "new_refresh",
            "expires_in":    3600,
        }
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(tokenData); err != nil {
            t.Fatalf("failed to encode token: %v", err)
        }
    }))
    defer ts.Close()

    cfg := &Config{
        ClientID:     "testclient",
        ClientSecret: "secret",
        Endpoint: Endpoint{
            TokenURL: ts.URL,
        },
    }
    ctx := context.WithValue(context.Background(), HTTPClient, ts.Client())
    // Wrap the token source with an expiry buffer of 1 minute.
    src := cfg.TokenSource(ctx, nearExpiryToken)
    tsrc := ReuseTokenSourceWithExpiry(nearExpiryToken, src, 1*time.Minute)
    renewedToken, err := tsrc.Token()
    if err != nil {
        t.Fatalf("expected no error, got %v", err)
    }
    if renewedToken.AccessToken != "renewed_early" {
        t.Errorf("expected access token 'renewed_early', got %s", renewedToken.AccessToken)
    }
    if callCount != 1 {
        t.Errorf("expected refresh call count 1, got %d", callCount)
    }
}
// roundTripFunc is a helper type that allows using ordinary functions as http.RoundTripper.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
    return f(req)
}
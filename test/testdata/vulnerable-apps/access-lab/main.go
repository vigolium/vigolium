// Command access-lab is a DELIBERATELY VULNERABLE web application used to
// exercise the durable-autopilot agent against the class of bugs a native,
// unauthenticated scanner cannot find on its own: authenticated IDOR / BOLA
// (horizontal privilege escalation) and broken access control (vertical
// privilege escalation). It is intentionally insecure — do not deploy it.
//
// Ground truth (asserted by scripts/e2e-autopilot-access.sh):
//
//	V1 IDOR   GET /api/users/{id}   — any logged-in user reads any other user's
//	                                  PII (email/address) by changing {id}. No
//	                                  ownership check.
//	V2 IDOR   GET /api/orders/{id}  — any logged-in user reads any order (incl.
//	                                  its secret note) by changing {id}. No
//	                                  ownership check.
//	V3 BAC    GET /admin/dashboard  — a normal (role=user) session reaches the
//	                                  admin-only dashboard, which leaks every
//	                                  user + a flag. Missing role check.
//	V4 BAC    POST /admin/promote   — a normal user can promote any account to
//	                                  admin (privilege escalation). Missing role
//	                                  check on a state-changing action.
//	V5 DOMXSS GET /welcome?name=     — the server response is static; the inline
//	                                  script reads location.search and writes it
//	                                  to innerHTML. Browser-only: a reflection
//	                                  scanner sees no reflection in the response.
//	V6 STORED POST /api/reviews then — multi-step: authenticate, store a review
//	          GET /product            comment, then the product page fetches it
//	                                  and injects it via innerHTML (executes in
//	                                  any viewer's browser).
//	V7 MASSA  PATCH /api/me           — mass assignment: arbitrary JSON fields are
//	                                  merged into your own record, so you can set
//	                                  your own `credits` (or `role`) — a logic bug
//	                                  a native scan won't attempt.
//
// Accounts (username / password / id / role):
//
//	wiener / peter    / 1   / user   (the low-priv attacker account)
//	carlos / hunter2  / 2   / user   (a victim account)
//	admin  / admin123 / 100 / admin
//
// Login: POST /login with form or JSON {"username","password"} -> sets a
// `session` cookie. All /api/* and /admin/* routes require that cookie (so the
// bugs are AUTHENTICATED — the whole point) but skip the per-object / per-role
// authorization that should follow.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type user struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	password string // never serialized
	Role     string `json:"role"`
	Email    string `json:"email"`
	Address  string `json:"address"`
	Credits  int    `json:"credits"`
}

type order struct {
	ID      int    `json:"id"`
	OwnerID int    `json:"owner_id"`
	Item    string `json:"item"`
	Total   string `json:"total"`
	Secret  string `json:"secret_note"` // sensitive; proves the IDOR leaked real data
}

// review is a user-submitted product comment. Comments are stored verbatim and
// rendered into the product page via innerHTML — the stored-XSS sink (V6).
type review struct {
	Author  string `json:"author"`
	Product string `json:"product"`
	Comment string `json:"comment"`
}

// adminFlag is the sensitive value only an admin should ever see. The autopilot
// reaching it as a normal user is the unambiguous proof of V3.
const adminFlag = "FLAG{broken-access-control-vertical-privesc}"

var (
	mu       sync.Mutex
	users    = map[int]*user{}
	byName   = map[string]*user{}
	orders   = map[int]*order{}
	reviews  []review
	sessions = map[string]int{} // token -> userID
	seq      int
)

func seed() {
	add := func(u *user) { users[u.ID] = u; byName[u.Username] = u }
	add(&user{ID: 1, Username: "wiener", password: "peter", Role: "user", Email: "wiener@access.lab", Address: "1 Attacker St", Credits: 10})
	add(&user{ID: 2, Username: "carlos", password: "hunter2", Role: "user", Email: "carlos@access.lab", Address: "2 Victim Ave", Credits: 50})
	add(&user{ID: 100, Username: "admin", password: "admin123", Role: "admin", Email: "admin@access.lab", Address: "HQ", Credits: 0})
	orders[1001] = &order{ID: 1001, OwnerID: 1, Item: "Padlock", Total: "$9.99", Secret: "wiener's shipping notes"}
	orders[1002] = &order{ID: 1002, OwnerID: 2, Item: "Diamond", Total: "$5000.00", Secret: "carlos home delivery code 4417"}
	orders[1003] = &order{ID: 100*10 + 3, OwnerID: 100, Item: "Server", Total: "$12000.00", Secret: "admin infra credentials"}
	reviews = append(reviews, review{Author: "carlos", Product: "diamond", Comment: "Beautiful, fast shipping!"})
}

func newToken() string {
	seq++
	return fmt.Sprintf("sess-%d-%d", time.Now().UnixNano(), seq)
}

// currentUser resolves the session cookie to a user, or nil.
func currentUser(r *http.Request) *user {
	c, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	uid, ok := sessions[c.Value]
	if !ok {
		return nil
	}
	return users[uid]
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><title>Access Lab</title></head><body>
<h1>Access Lab</h1>
<p>A deliberately vulnerable shop for authorization testing.</p>
<h2>Log in</h2>
<form method="POST" action="/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button type="submit">Login</button>
</form>
<h2>API (require the <code>session</code> cookie)</h2>
<ul>
  <li>GET <a href="/api/me">/api/me</a> — your profile</li>
  <li>GET /api/users/{id} — a user's profile</li>
  <li>GET /api/orders/{id} — an order</li>
  <li>GET /admin/dashboard — admin dashboard</li>
  <li>POST /admin/promote?user={id} — grant admin</li>
  <li>PATCH /api/me — update your profile (JSON body)</li>
  <li>GET/POST /api/reviews — product reviews (JSON)</li>
</ul>
<h2>Pages</h2>
<ul>
  <li>GET <a href="/welcome">/welcome</a> — client-rendered greeting (reads ?name=)</li>
  <li>GET <a href="/product">/product</a> — product page, renders reviews</li>
</ul>
</body></html>`)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var username, password string
	ct := r.Header.Get("Content-Type")
	if len(ct) >= 16 && ct[:16] == "application/json" {
		var body struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		username, password = body.Username, body.Password
	} else {
		_ = r.ParseForm()
		username, password = r.PostFormValue("username"), r.PostFormValue("password")
	}

	mu.Lock()
	u := byName[username]
	if u == nil || u.password != password {
		mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	tok := newToken()
	sessions[tok] = u.ID
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: "session", Value: tok, Path: "/", HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]any{"id": u.ID, "username": u.Username, "role": u.Role})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// handleUser is V1: it authenticates the caller but never checks that the
// requested {id} belongs to them — classic IDOR / BOLA.
func handleUser(w http.ResponseWriter, r *http.Request) {
	if currentUser(r) == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	id, _ := strconv.Atoi(r.PathValue("id"))
	mu.Lock()
	u := users[id]
	mu.Unlock()
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
		return
	}
	writeJSON(w, http.StatusOK, u) // BUG: no ownership check
}

// handleOrder is V2: same IDOR, on an order object with a sensitive note.
func handleOrder(w http.ResponseWriter, r *http.Request) {
	if currentUser(r) == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	id, _ := strconv.Atoi(r.PathValue("id"))
	mu.Lock()
	o := orders[id]
	mu.Unlock()
	if o == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such order"})
		return
	}
	writeJSON(w, http.StatusOK, o) // BUG: no ownership check
}

// handleAdminDashboard is V3: authenticated but NOT role-gated, so any user
// reaches the admin-only surface and its flag.
func handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	// BUG: should require u.Role == "admin".
	mu.Lock()
	all := make([]*user, 0, len(users))
	for _, x := range users {
		all = append(all, x)
	}
	mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"flag":        adminFlag,
		"viewer":      u.Username,
		"viewer_role": u.Role,
		"users":       all,
	})
}

// handleAdminPromote is V4: a state-changing admin action with no role check.
func handleAdminPromote(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	// BUG: should require u.Role == "admin".
	id, _ := strconv.Atoi(r.URL.Query().Get("user"))
	mu.Lock()
	target := users[id]
	if target != nil {
		target.Role = "admin"
	}
	mu.Unlock()
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"promoted": target.Username, "role": target.Role, "by": u.Username})
}

// handleWelcome is V5: DOM-based XSS. The server response is STATIC — the
// `name` value never appears in the HTML the server sends, so a reflection-based
// native scanner sees nothing reflected. Only a browser executing the inline
// script (which reads location.search and writes it to innerHTML) fires the
// payload, e.g. GET /welcome?name=<img src=x onerror=alert(document.domain)>.
func handleWelcome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><title>Welcome</title></head><body>
<h1>Welcome</h1>
<div id="greeting">Hello, guest</div>
<script>
  // DOM XSS sink: the ?name= param is written to innerHTML with no encoding.
  var n = new URLSearchParams(location.search).get('name');
  if (n) { document.getElementById('greeting').innerHTML = 'Hello, ' + n; }
</script>
</body></html>`)
}

// handleProduct is the render half of V6 (stored XSS). It serves a static page
// whose script fetches stored reviews and injects each comment via innerHTML —
// so a comment posted with a script payload executes in any viewer's browser.
func handleProduct(w http.ResponseWriter, r *http.Request) {
	product := r.URL.Query().Get("name")
	if product == "" {
		product = "diamond"
	}
	pj, _ := json.Marshal(product) // safe JS string literal for the product name
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>Product</title></head><body>
<h1>Product reviews</h1>
<div id="reviews">loading…</div>
<script>
  fetch('/api/reviews?product=' + encodeURIComponent(%s), {credentials: 'include'})
    .then(function (r) { return r.json(); })
    .then(function (list) {
      // Stored XSS sink: each review comment injected via innerHTML, unescaped.
      document.getElementById('reviews').innerHTML =
        (list || []).map(function (x) { return '<div class="review">' + x.comment + '</div>'; }).join('');
    });
</script>
</body></html>`, string(pj))
}

// handleReviewsGet returns stored reviews (optionally filtered by product).
// Reviews are PUBLIC (like a real shop) so the product page renders them for any
// visitor — which is what makes the stored comment (V6) execute in a plain
// browser visit. The injection half (POST) still requires a login.
func handleReviewsGet(w http.ResponseWriter, r *http.Request) {
	product := r.URL.Query().Get("product")
	mu.Lock()
	out := make([]review, 0, len(reviews))
	for _, rv := range reviews {
		if product == "" || rv.Product == product {
			out = append(out, rv)
		}
	}
	mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// handleReviewsPost stores a review comment verbatim — the injection half of V6.
func handleReviewsPost(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	var body struct{ Product, Comment string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Comment == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "comment required"})
		return
	}
	if body.Product == "" {
		body.Product = "diamond"
	}
	mu.Lock()
	reviews = append(reviews, review{Author: u.Username, Product: body.Product, Comment: body.Comment}) // BUG: stored unsanitized
	mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "review stored", "product": body.Product})
}

// handlePatchMe is V7: mass assignment. Every field in the JSON body is merged
// into the caller's own record — including `credits` and `role`, which the
// client must never control. So PATCH /api/me {"credits":999999} grants unlimited
// store credit (and {"role":"admin"} self-escalates).
func handlePatchMe(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		return
	}
	var patch map[string]any
	if json.NewDecoder(r.Body).Decode(&patch) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	mu.Lock()
	// BUG: no allowlist — every provided field is applied.
	if v, ok := patch["email"].(string); ok {
		u.Email = v
	}
	if v, ok := patch["address"].(string); ok {
		u.Address = v
	}
	if v, ok := patch["credits"].(float64); ok {
		u.Credits = int(v)
	}
	if v, ok := patch["role"].(string); ok {
		u.Role = v
	}
	updated := *u
	mu.Unlock()
	writeJSON(w, http.StatusOK, &updated)
}

func main() {
	seed()
	addr := ":9899"
	if v := os.Getenv("ACCESS_LAB_ADDR"); v != "" {
		addr = v
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("GET /api/me", handleMe)
	mux.HandleFunc("GET /api/users/{id}", handleUser)
	mux.HandleFunc("GET /api/orders/{id}", handleOrder)
	mux.HandleFunc("GET /admin/dashboard", handleAdminDashboard)
	mux.HandleFunc("POST /admin/promote", handleAdminPromote)
	mux.HandleFunc("PATCH /api/me", handlePatchMe)
	mux.HandleFunc("GET /api/reviews", handleReviewsGet)
	mux.HandleFunc("POST /api/reviews", handleReviewsPost)
	mux.HandleFunc("GET /welcome", handleWelcome)
	mux.HandleFunc("GET /product", handleProduct)

	log.Printf("access-lab (deliberately vulnerable) listening on %s", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// Global axios calls
axios.get("/api/global/users");
axios.post("/api/global/users", { name: "alice", role: "admin" });
axios.delete("/api/global/users/42");

// axios(config) form
axios({
  url: "/api/config-form/login",
  method: "POST",
  data: { username: "bob", password: "secret" },
  headers: { "Content-Type": "application/json", "X-App": "demo" },
});

// axios(url, config) form
axios("/api/url-config/profile", { method: "PUT", params: { expand: "all" } });

// Instance with baseURL — relative URLs must be joined onto baseURL.
const api = axios.create({
  baseURL: "https://api.example.com/v2",
  headers: { Authorization: "Bearer token123" },
});

api.get("/users");
api.post("/users", { email: "carol@example.com" });
api.get("/items", { params: { page: 2 } });

// Absolute URL on an instance must ignore baseURL.
api.get("https://other.example.com/health");

// instance.request(config)
api.request({ url: "/request-form/data", method: "PATCH", data: { ok: true } });

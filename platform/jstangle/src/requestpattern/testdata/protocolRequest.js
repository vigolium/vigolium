const ws = new WebSocket("wss://realtime.example.com/socket?token=abc");
const sse = new EventSource("https://events.example.com/stream");
navigator.sendBeacon("/analytics/collect", JSON.stringify({ event: "pageview", page: "/home" }));
const ws2 = new window.WebSocket("wss://realtime.example.com/v2");

// GraphQL over fetch (POST with query/operationName in the body) — should be
// captured by the existing fetch body extraction, no special-casing needed.
fetch("/graphql", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ operationName: "GetUser", query: "query GetUser { user { id } }" }),
});

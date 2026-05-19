// Test case 1: Variable used with POST method and params object
const apiUrl = "/api/users";
callApi(apiUrl, "POST", {}, {}, { userId: 123, name: "test" });

// Test case 2: Variable used with GET method
const getUrl = "/api/data";
fetchData(getUrl, "GET", { page: 1 });

// Test case 3: Variable with JSON.stringify body
const postUrl = "/api/create";
sendRequest(postUrl, "POST", {}, {}, JSON.stringify({ data: "value" }));

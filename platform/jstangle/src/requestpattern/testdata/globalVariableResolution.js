// Test case: Global variable resolution for URLs
// This tests that variables like API_URL and BOB_URL are resolved from global config objects
// Pattern from real-world Angular apps (e.g., www.hyattconnect.com)

var config = {
    production: true,
    API_URL: "/site-visits-api",
    BOB_URL: "/bob"
};

var http = {
    post: function(url, data) { return Promise.resolve(); },
    get: function(url, options) { return Promise.resolve(); }
};

function NotificationService() {
    this.API_URL = config.API_URL;
    this.BOB_URL = config.BOB_URL;
}

NotificationService.prototype.save = function(data) {
    return http.post(this.API_URL + "/notification/save", {data: data});
};

NotificationService.prototype.getTimezone = function(tz) {
    return http.get(this.BOB_URL + "/service/timezone/" + tz);
};

var svc = new NotificationService();
svc.save({msg: "test"});
svc.getTimezone("UTC");

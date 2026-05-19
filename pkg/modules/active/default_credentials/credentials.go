package default_credentials

// credentialPair represents a username/password combination to test.
type credentialPair struct {
	username string
	password string
}

// defaultCredentials is the list of common default credential pairs to test.
var defaultCredentials = []credentialPair{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"admin", "123456"},
	{"admin", ""},
	{"root", "root"},
	{"root", "toor"},
	{"root", "password"},
	{"test", "test"},
	{"user", "user"},
	{"guest", "guest"},
	{"demo", "demo"},
	{"administrator", "administrator"},
	{"admin", "changeme"},
	{"admin", "letmein"},
	{"tomcat", "tomcat"},
	{"tomcat", "s3cret"},
	{"manager", "manager"},
	{"admin", "default"},
	{"postgres", "postgres"},
}

// usernameParamNames are parameter names that typically hold usernames.
var usernameParamNames = []string{
	"username", "user", "email", "login", "user_name",
	"userid", "user_id", "uname", "account", "name",
}

// passwordParamNames are parameter names that typically hold passwords.
var passwordParamNames = []string{
	"password", "passwd", "pass", "pwd", "user_password",
	"user_pass", "secret", "passw",
}

// loginPathPatterns are URL path segments that suggest a login endpoint.
var loginPathPatterns = []string{
	"/login", "/signin", "/sign-in", "/auth",
	"/authenticate", "/session", "/api/login",
	"/api/auth", "/api/signin", "/user/login",
	"/account/login", "/admin/login",
}

// successIndicators are strings that suggest successful authentication.
var successIndicators = []string{
	"welcome", "dashboard", "logged in", "success",
	"authenticated", "my account", "profile",
	"logout", "sign out", "log out",
}

// lockoutIndicators are strings that suggest account lockout or rate limiting.
var lockoutIndicators = []string{
	"locked", "too many", "rate limit", "blocked",
	"temporarily", "try again later", "exceeded",
	"brute", "captcha required",
}

// captchaIndicators are strings that suggest CAPTCHA is present.
var captchaIndicators = []string{
	"captcha", "recaptcha", "hcaptcha", "g-recaptcha",
	"cf-turnstile", "challenge",
}

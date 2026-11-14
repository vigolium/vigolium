package safety

import "testing"

func TestDestructiveAndLogout(t *testing.T) {
	for _, s := range []string{"Log out", "/signout", "Sign Out", "log-off", "/account/delete", "Delete item", "Remove", "/x/remove", "Deactivate account", "unsubscribe", "close_account", "Cancel account"} {
		if !IsDestructiveName(s) {
			t.Errorf("%q should be destructive", s)
		}
	}
	for _, s := range []string{"Next", "/products", "Search", "unremovable", "Settings"} {
		if IsDestructiveName(s) {
			t.Errorf("%q should not be destructive", s)
		}
	}
	if !IsLogoutName("Sign out") || IsLogoutName("Delete") {
		t.Error("logout subset wrong")
	}
	if got := JSRegexLiteral(`a/b`); got != `/a\/b/i` {
		t.Errorf("JSRegexLiteral = %s", got)
	}
}

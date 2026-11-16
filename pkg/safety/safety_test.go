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
	// Commit actions are destructive; the navigation that leads to them is not.
	for _, s := range []string{"Pay now", "pay", "/billing/pay", "Place order", "Place your order", "Buy now", "Purchase",
		"Confirm payment", "Complete purchase", "Transfer funds", "Wire transfer", "Send money", "Send invitation",
		"Invite", "Approve", "Publish"} {
		if !IsDestructiveName(s) {
			t.Errorf("%q should be destructive (an irreversible commit)", s)
		}
	}
	for _, s := range []string{"Checkout", "/cart", "Payment methods", "/payments/history", "Send", "Invitations", "Unpublish", "Approved items", "Paypal"} {
		if IsDestructiveName(s) {
			t.Errorf("%q should not be destructive (navigation, not a commit)", s)
		}
	}
	if !IsLogoutName("Sign out") || IsLogoutName("Delete") {
		t.Error("logout subset wrong")
	}
	if got := JSRegexLiteral(`a/b`); got != `/a\/b/i` {
		t.Errorf("JSRegexLiteral = %s", got)
	}
}

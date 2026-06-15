package firebase_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

type firebaseProbe struct {
	path string
	name string
	// markers is an AND-of-OR group set (see modkit.MatchAllGroups): the body must
	// contain at least one substring from EVERY group. Firebase config files share
	// generic keys ("headers"/"redirects"/"rules"/"project_id") with arbitrary
	// JSON, so each probe anchors on a Firebase-specific token and corroborates
	// with a second group instead of firing on any single weak key.
	markers     [][]string
	antiMarkers []string // if any match, skip (FP indicator)
	sev         severity.Severity
	desc        string
}

var firebaseProbes = []firebaseProbe{
	// Firebase Hosting reserved URL - project config
	{
		path:        "/__/firebase/init.json",
		name:        "Firebase Project Config Exposed (init.json)",
		markers:     [][]string{{"apiKey", "messagingSenderId", "authDomain"}, {"projectId", "storageBucket", "appId"}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "<HTML"},
		sev:         severity.Medium,
		desc:        "Firebase Hosting init.json endpoint exposes project configuration including API key, project ID, and service endpoints",
	},
	{
		path:        "/__/firebase/init.js",
		name:        "Firebase Project Config Exposed (init.js)",
		markers:     [][]string{{"firebase.initializeApp", "firebaseConfig"}, {"apiKey", "projectId"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Firebase Hosting init.js endpoint exposes project configuration as JavaScript",
	},
	// Firebase deployment config — anchor on a Firebase target, corroborate with a
	// directive, so a generic JSON carrying only "headers"/"redirects" cannot match.
	{
		path:        "/firebase.json",
		name:        "Firebase Deployment Config Exposed",
		markers:     [][]string{{"hosting", "functions", "emulators", "firestore", "storage"}, {"rewrites", "redirects", "headers", "predeploy", "public"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Firebase CLI configuration file exposed, revealing hosting rewrites, function mappings, and deployment structure",
	},
	// Security rules files — the "service ..."/"match ..." preamble is unique; drop
	// the generic "allow read"/"allow write" which appear in any ruleset.
	{
		path:        "/firestore.rules",
		name:        "Firestore Security Rules Exposed",
		markers:     [][]string{{"service cloud.firestore", "match /databases/"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Firestore security rules source file exposed, revealing authorization logic and potential bypass opportunities",
	},
	{
		path:        "/storage.rules",
		name:        "Firebase Storage Rules Exposed",
		markers:     [][]string{{"service firebase.storage", "match /b/"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Firebase Storage security rules exposed, revealing access control logic for cloud storage",
	},
	{
		path: "/database.rules.json",
		name: "RTDB Security Rules Exposed",
		// Require BOTH the .read and .write rule keys (the dotted RTDB syntax), not
		// a bare "rules" key that any JSON config might carry.
		markers:     [][]string{{".read"}, {".write"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Firebase Realtime Database security rules exposed, revealing read/write authorization logic",
	},
	// Index definitions
	{
		path:        "/firestore.indexes.json",
		name:        "Firestore Index Definitions Exposed",
		markers:     [][]string{{"collectionGroup", "indexes"}, {"fields", "queryScope", "order"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Firestore index definitions exposed, revealing collection names and query patterns",
	},
	// Runtime config — the file has arbitrary user keys, so content cannot strongly
	// anchor it; at minimum require a keyed JSON object, not a bare "{".
	{
		path:        "/.runtimeconfig.json",
		name:        "Firebase Runtime Config Exposed",
		markers:     [][]string{{"{"}, {`":`}},
		antiMarkers: []string{"<html", "<!DOCTYPE", "Cannot GET", "Not Found"},
		sev:         severity.High,
		desc:        "Firebase Cloud Functions runtime config exposed, potentially containing third-party API keys and service credentials",
	},
	// Service account keys — require the private key plus a second key-file field.
	{
		path:        "/serviceAccountKey.json",
		name:        "Firebase Service Account Key Exposed",
		markers:     [][]string{{"private_key"}, {"client_email", "service_account", "private_key_id"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Firebase Admin SDK service account private key exposed — potential full Firebase/Google Cloud takeover",
	},
	{
		path:        "/firebase-adminsdk.json",
		name:        "Firebase Admin SDK Key Exposed",
		markers:     [][]string{{"private_key"}, {"client_email", "service_account", "private_key_id"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Firebase Admin SDK credential file exposed — potential full Firebase/Google Cloud takeover",
	},
	{
		path:        "/credentials.json",
		name:        "Google Credentials File Exposed",
		markers:     [][]string{{"private_key"}, {"client_email", "service_account", "project_id"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Google service account credentials file exposed with private key material",
	},
	// Mobile config files
	{
		path:        "/google-services.json",
		name:        "Android Firebase Config Exposed",
		markers:     [][]string{{"mobilesdk_app_id", "current_key"}, {"project_id", "storage_bucket", "client_id"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Android Firebase configuration file exposed, revealing project identifiers and API keys",
	},
	{
		path:        "/GoogleService-Info.plist",
		name:        "iOS Firebase Config Exposed",
		markers:     [][]string{{"GOOGLE_APP_ID", "GCM_SENDER_ID"}, {"API_KEY", "PROJECT_ID", "BUNDLE_ID"}},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "iOS Firebase configuration plist exposed, revealing project identifiers and API keys",
	},
}

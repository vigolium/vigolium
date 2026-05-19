package firebase_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

type firebaseProbe struct {
	path        string
	name        string
	markers     []string // at least one must match
	antiMarkers []string // if any match, skip (FP indicator)
	sev         severity.Severity
	desc        string
}

var firebaseProbes = []firebaseProbe{
	// Firebase Hosting reserved URL - project config
	{
		path:        "/__/firebase/init.json",
		name:        "Firebase Project Config Exposed (init.json)",
		markers:     []string{"projectId", "apiKey", "authDomain", "storageBucket", "messagingSenderId"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "<HTML"},
		sev:         severity.Medium,
		desc:        "Firebase Hosting init.json endpoint exposes project configuration including API key, project ID, and service endpoints",
	},
	{
		path:        "/__/firebase/init.js",
		name:        "Firebase Project Config Exposed (init.js)",
		markers:     []string{"firebase.initializeApp", "apiKey", "projectId"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Firebase Hosting init.js endpoint exposes project configuration as JavaScript",
	},
	// Firebase deployment config
	{
		path:        "/firebase.json",
		name:        "Firebase Deployment Config Exposed",
		markers:     []string{"hosting", "rewrites", "redirects", "headers", "functions"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Firebase CLI configuration file exposed, revealing hosting rewrites, function mappings, and deployment structure",
	},
	// Security rules files
	{
		path:        "/firestore.rules",
		name:        "Firestore Security Rules Exposed",
		markers:     []string{"service cloud.firestore", "match /databases/", "allow read", "allow write"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Firestore security rules source file exposed, revealing authorization logic and potential bypass opportunities",
	},
	{
		path:        "/storage.rules",
		name:        "Firebase Storage Rules Exposed",
		markers:     []string{"service firebase.storage", "match /b/", "allow read", "allow write"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Firebase Storage security rules exposed, revealing access control logic for cloud storage",
	},
	{
		path:        "/database.rules.json",
		name:        "RTDB Security Rules Exposed",
		markers:     []string{".read", ".write", "rules"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Firebase Realtime Database security rules exposed, revealing read/write authorization logic",
	},
	// Index definitions
	{
		path:        "/firestore.indexes.json",
		name:        "Firestore Index Definitions Exposed",
		markers:     []string{"indexes", "collectionGroup", "fields"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Firestore index definitions exposed, revealing collection names and query patterns",
	},
	// Runtime config
	{
		path:        "/.runtimeconfig.json",
		name:        "Firebase Runtime Config Exposed",
		markers:     []string{"{"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "Cannot GET", "Not Found"},
		sev:         severity.High,
		desc:        "Firebase Cloud Functions runtime config exposed, potentially containing third-party API keys and service credentials",
	},
	// Service account keys
	{
		path:        "/serviceAccountKey.json",
		name:        "Firebase Service Account Key Exposed",
		markers:     []string{"service_account", "private_key", "client_email"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Firebase Admin SDK service account private key exposed — potential full Firebase/Google Cloud takeover",
	},
	{
		path:        "/firebase-adminsdk.json",
		name:        "Firebase Admin SDK Key Exposed",
		markers:     []string{"service_account", "private_key", "client_email"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Firebase Admin SDK credential file exposed — potential full Firebase/Google Cloud takeover",
	},
	{
		path:        "/credentials.json",
		name:        "Google Credentials File Exposed",
		markers:     []string{"service_account", "private_key", "client_email", "project_id"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Google service account credentials file exposed with private key material",
	},
	// Mobile config files
	{
		path:        "/google-services.json",
		name:        "Android Firebase Config Exposed",
		markers:     []string{"project_id", "mobilesdk_app_id", "current_key", "storage_bucket"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Android Firebase configuration file exposed, revealing project identifiers and API keys",
	},
	{
		path:        "/GoogleService-Info.plist",
		name:        "iOS Firebase Config Exposed",
		markers:     []string{"GOOGLE_APP_ID", "API_KEY", "GCM_SENDER_ID", "PROJECT_ID"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "iOS Firebase configuration plist exposed, revealing project identifiers and API keys",
	},
}

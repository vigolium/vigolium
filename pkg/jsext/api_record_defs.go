package jsext

// recordFuncDefs returns metadata-only definitions for vigolium.record.* functions.
// These are registered dynamically per-record by the execution context, so
// MakeHandler is nil — entries exist only for catalog/documentation purposes.
func recordFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace:   NsRecord,
			Name:        "uuid",
			Category:    CatRecord,
			Signature:   ".uuid",
			Returns:     "string",
			Description: "Database UUID of the current HTTP record being processed. Empty string if not persisted.",
			Example:     exRecordUUID,
			MakeHandler: nil,
		},
		{
			Namespace:   NsRecord,
			Name:        "annotate",
			Category:    CatRecord,
			Signature:   ".annotate(patch: {risk_score?, remarks?})",
			Returns:     "bool",
			Description: "Replace annotations (risk score and/or remarks) on the current HTTP record. Risk score is clamped to [0, 100].",
			Example:     exRecordAnnotate,
			MakeHandler: nil,
		},
		{
			Namespace:   NsRecord,
			Name:        "addRiskScore",
			Category:    CatRecord,
			Signature:   ".addRiskScore(delta: number)",
			Returns:     "bool",
			Description: "Increment risk_score by delta (can be negative). Result is clamped to [0, 100].",
			Example:     exRecordAddRiskScore,
			MakeHandler: nil,
		},
		{
			Namespace:   NsRecord,
			Name:        "addRemarks",
			Category:    CatRecord,
			Signature:   ".addRemarks(remarks: string[])",
			Returns:     "bool",
			Description: "Append remarks to the current HTTP record with deduplication. Existing remarks are preserved.",
			Example:     exRecordAddRemarks,
			MakeHandler: nil,
		},
	}
}

// configFuncDefs returns metadata-only definitions for vigolium.config.<key>.
// Config values are set dynamically from extensions.variables config, so
// MakeHandler is nil — entries exist only for catalog/documentation purposes.
func configFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace:   NsConfig,
			Name:        "<key>",
			Category:    CatConfig,
			Signature:   ".<key>",
			Returns:     "string",
			Description: "Access custom variables defined in extensions.variables config.",
			Example:     exConfigKey,
			MakeHandler: nil,
		},
	}
}

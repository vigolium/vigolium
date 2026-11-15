package cli

import (
	"reflect"

	"github.com/vigolium/vigolium/pkg/contract"
)

// commandTraits declares, for every runnable command, everything the machine
// contract needs to know about it, in one place:
//
//   - Kind: the -j output it owes (see machine.go).
//   - DB: what it does with the store — "read" opens the read pool
//     (query_only, no journal-mode change, no checkpointing) so the command
//     never waits on a scan writing the same file; "write" is the behaviour
//     every command had before intents existed; "none" has no reason to open
//     the store (if one does anyway it gets write intent, so "none" can never
//     make an open stricter). Only commands that provably never write belong
//     under "read": a write through the read pool fails loudly.
//   - Shape: how its -j rows can be narrowed (--fields, --compact,
//     --max-output-bytes, -n/--offset); see shaping_traits.go.
//   - SendsTraffic: its job is to send requests to a target. Its document says
//     `sends_traffic: true`, and a follow-up `query` never names it: a hint is
//     something to run without thinking, and re-sending is not that.
//
// Keyed by cobra path without the root name; "" is the root itself. One table
// rather than a declaration in each command file: the contract tests walk the
// finished tree against it, so an added command that nobody classified fails
// there, and the whole surface can be reviewed in one place. machineKinds,
// dbIntents and sendsTrafficCommands are views derived from it.
var commandTraits = map[string]commandTrait{
	// Help-only groups, cobra's own commands, passthrough shims (they re-enter
	// the tree as the translated command, which declares its own intent), the
	// TUIs and the long-running server are interactive. Pure groups print help
	// for a human and are a usage error under -j (enforceGroupSubcommands).
	"":                      {Kind: kindInteractive, DB: dbNone},
	"agent":                 {Kind: kindRead, DB: dbNone, Shape: noShape("three listings (--list-agents, --list-templates, --list-modes) with different rows")},
	"agent audit":           {Kind: kindScan, DB: dbWrite, Shape: noShape("an agent run document")},
	"agent autopilot":       {Kind: kindScan, DB: dbWrite, SendsTraffic: true, Shape: noShape("an agent run document")},
	"agent cancel":          {Kind: kindMutation, DB: dbWrite},
	"agent olium":           {Kind: kindInteractive, DB: dbWrite},
	"agent query":           {Kind: kindRead, DB: dbWrite, Shape: noShape("one model answer")},
	"agent session":         {Kind: kindRead, DB: dbRead, Shape: rowsShape().pagedByQuery()},
	"agent swarm":           {Kind: kindScan, DB: dbWrite, SendsTraffic: true, Shape: noShape("an agent run document")},
	"agent triage":          {Kind: kindMutation, DB: dbWrite, SendsTraffic: true},
	"arjun":                 {Kind: kindInteractive, DB: dbNone},
	"audit":                 {Kind: kindScan, DB: dbWrite, Shape: noShape("an agent run document")},
	"auth":                  {Kind: kindInteractive, DB: dbNone},
	"auth check":            {Kind: kindRead, DB: dbRead, SendsTraffic: true, Shape: rowsShape().vocabFrom(sessionCheckItem{})},
	"auth lint":             {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"auth list":             {Kind: kindRead, DB: dbRead, Shape: rowsShape().vocabFrom(authSessionView{})},
	"auth load":             {Kind: kindMutation, DB: dbWrite},
	"auth rm":               {Kind: kindMutation, DB: dbWrite},
	"auth show":             {Kind: kindRead, DB: dbRead, Shape: rowsShape()},
	"auth totp":             {Kind: kindRead, DB: dbNone, Shape: noShape("one code")},
	"completion":            {Kind: kindInteractive, DB: dbNone},
	"completion bash":       {Kind: kindInteractive, DB: dbNone},
	"completion fish":       {Kind: kindInteractive, DB: dbNone},
	"completion powershell": {Kind: kindInteractive, DB: dbNone},
	"completion zsh":        {Kind: kindInteractive, DB: dbNone},
	"config":                {Kind: kindInteractive, DB: dbNone},
	"config clean":          {Kind: kindMutation, DB: dbNone},
	"config env":            {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"config get":            {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"config ls":             {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"config set":            {Kind: kindMutation, DB: dbNone},
	"config unset":          {Kind: kindMutation, DB: dbNone},
	// Reads recent scan targets for one rule; a missing store skips it.
	"config validate":    {Kind: kindRead, DB: dbRead, Shape: rowsShape()},
	"db":                 {Kind: kindInteractive, DB: dbNone},
	"db clean":           {Kind: kindMutation, DB: dbWrite},
	"db compact":         {Kind: kindMutation, DB: dbWrite},
	"db export":          {Kind: kindStream, DB: dbRead, Shape: noShape("records stream to a file or stdout; the -j document is a receipt")},
	"db list":            {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned().pagedByQuery()},
	"db migrate":         {Kind: kindMutation, DB: dbWrite},
	"db reset":           {Kind: kindMutation, DB: dbWrite},
	"db seed":            {Kind: kindMutation, DB: dbWrite},
	"db stats":           {Kind: kindRead, DB: dbRead, Shape: objectShape()},
	"dig":                {Kind: kindInteractive, DB: dbNone},
	"dns":                {Kind: kindRead, DB: dbWrite, Shape: rowsShape().owned().unpaged("sends DNS queries: a second page would resolve again")},
	"doctor":             {Kind: kindRead, DB: dbRead, Shape: rowsShape()},
	"endpoints":          {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned().pagedByQuery()},
	"export":             {Kind: kindStream, DB: dbRead, Shape: noShape("records stream to a file or stdout; the -j document is a receipt")},
	"extensions":         {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"extensions docs":    {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"extensions eval":    {Kind: kindRead, DB: dbWrite, Shape: noShape("one script result")},
	"extensions example": {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"extensions lint":    {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"extensions ls":      {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"extensions preset":  {Kind: kindMutation, DB: dbNone},
	// Also `extensions eval --record-uuid`, which opens the read pool itself.
	"extensions run":   {Kind: kindRead, DB: dbRead, Shape: rowsShape()},
	"extensions test":  {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"extensions types": {Kind: kindRead, DB: dbNone, Shape: objectShape()},
	"ffuf":             {Kind: kindInteractive, DB: dbNone},
	"finding":          {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned().pagedByQuery()},
	"finding load":     {Kind: kindMutation, DB: dbWrite},
	"finding mark":     {Kind: kindMutation, DB: dbWrite},
	"finding show":     {Kind: kindRead, DB: dbRead, Shape: objectShape()},
	"finding verify":   {Kind: kindMutation, DB: dbWrite, SendsTraffic: true},
	"fingerprint":      {Kind: kindScan, DB: dbWrite, SendsTraffic: true, Shape: scanDocumentShape},
	"fuzz":             {Kind: kindStream, DB: dbWrite, SendsTraffic: true, Shape: rowsShape().owned().unpaged("sends traffic: a second page would re-send every payload")},
	"gau":              {Kind: kindInteractive, DB: dbNone},
	"help":             {Kind: kindInteractive, DB: dbNone},
	"host":             {Kind: kindInteractive, DB: dbNone},
	"hosts":            {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned().pagedByQuery()},
	"import":           {Kind: kindMutation, DB: dbWrite},
	"ingest":           {Kind: kindMutation, DB: dbWrite},
	"init":             {Kind: kindMutation, DB: dbWrite},
	"js":               {Kind: kindRead, DB: dbWrite, Shape: noShape("one script result")},
	"katana":           {Kind: kindInteractive, DB: dbNone},
	"kit":              {Kind: kindInteractive, DB: dbNone},
	"kit harvest":      {Kind: kindRead, DB: dbNone, SendsTraffic: true, Shape: noShape("rows are plain URL strings")},
	"kit js-beautify":  {Kind: kindRead, DB: dbNone, Shape: noShape("one file's content")},
	"kit jwt-crack":    {Kind: kindRead, DB: dbNone, Shape: noShape("one result")},
	"kit oast":         {Kind: kindInteractive, DB: dbNone},
	"kit oast new":     {Kind: kindRead, DB: dbNone, Shape: noShape("one session's URLs")},
	"kit oast poll":    {Kind: kindRead, DB: dbNone, Shape: noShape("one session's interactions")},
	"kit param-mine":   {Kind: kindRead, DB: dbNone, SendsTraffic: true, Shape: rowsShape().vocabFrom(kitParamMineItem{})},
	"kit payload":      {Kind: kindRead, DB: dbNone, Shape: noShape("rows are plain strings")},
	"kit secret-scan":  {Kind: kindRead, DB: dbNone, Shape: rowsShape().vocabFrom(kitSecretMatch{})},
	"kit tmp-clean":    {Kind: kindMutation, DB: dbNone},
	"kit wordlist":     {Kind: kindRead, DB: dbNone, Shape: noShape("rows are plain strings")},
	// Bare `log` lists; `log <uuid>` prints a transcript.
	"log":             {Kind: kindRead, DB: dbRead, Shape: rowsShape()},
	"log ls":          {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned()},
	"match-not-found": {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned().unpaged("reads stdin once: there is no second read to page")},
	"module":          {Kind: kindRead, DB: dbNone, Shape: rowsShape().vocabFrom(moduleJSONEntry{}, moduleTagRow{}).drop("description", "confirmation_criteria")},
	"module disable":  {Kind: kindMutation, DB: dbNone},
	"module enable":   {Kind: kindMutation, DB: dbNone},
	"module ls":       {Kind: kindRead, DB: dbNone, Shape: rowsShape().vocabFrom(moduleJSONEntry{}, moduleTagRow{}).drop("description", "confirmation_criteria")},
	"module show":     {Kind: kindRead, DB: dbNone, Shape: objectShape()},
	"nuclei":          {Kind: kindInteractive, DB: dbNone},
	"oast":            {Kind: kindInteractive, DB: dbNone},
	// Ingested callbacks become findings of the scan that planted them.
	"oast ingest":     {Kind: kindMutation, DB: dbWrite},
	"oast poll":       {Kind: kindMutation, DB: dbWrite},
	"olium":           {Kind: kindInteractive, DB: dbWrite},
	"params":          {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned().pagedByQuery()},
	"project":         {Kind: kindInteractive, DB: dbNone},
	"project config":  {Kind: kindRead, DB: dbWrite, Shape: objectShape().vocabFrom(projectConfigView{})},
	"project create":  {Kind: kindMutation, DB: dbWrite},
	"project current": {Kind: kindRead, DB: dbRead, Shape: objectShape()},
	"project delete":  {Kind: kindMutation, DB: dbWrite},
	"project list":    {Kind: kindRead, DB: dbRead, Shape: rowsShape()},
	"project rename":  {Kind: kindMutation, DB: dbWrite},
	"project use":     {Kind: kindMutation, DB: dbWrite},
	// replay/fuzz stay "write": they read a stored request, but replay
	// --in-replace rewrites it and both are network commands whose DB touch is
	// incidental, so the read pool buys nothing.
	"replay":      {Kind: kindStream, DB: dbWrite, SendsTraffic: true, Shape: rowsShape().owned().pagedByQuery()},
	"run":         {Kind: kindScan, DB: dbWrite, SendsTraffic: true, Shape: scanDocumentShape},
	"scan":        {Kind: kindScan, DB: dbWrite, SendsTraffic: true, Shape: scanDocumentShape},
	"scan diff":   {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned()},
	"scan ls":     {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned()},
	"scan status": {Kind: kindRead, DB: dbRead, Shape: objectShape().drop("plan")},
	"scan stop":   {Kind: kindMutation, DB: dbWrite},
	// Polls during a scan: must never take the write lock.
	"scan wait":           {Kind: kindScan, DB: dbRead, Shape: scanDocumentShape},
	"scan-request":        {Kind: kindScan, DB: dbWrite, SendsTraffic: true, Shape: scanDocumentShape},
	"scan-url":            {Kind: kindScan, DB: dbWrite, SendsTraffic: true, Shape: scanDocumentShape},
	"schema":              {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"schema all":          {Kind: kindStream, DB: dbNone, Shape: noShape("a JSON Schema document")},
	"schema command":      {Kind: kindStream, DB: dbNone, Shape: noShape("a JSON Schema document")},
	"schema error":        {Kind: kindStream, DB: dbNone, Shape: noShape("a JSON Schema document")},
	"schema event":        {Kind: kindStream, DB: dbNone, Shape: noShape("a JSON Schema document")},
	"schema flags":        {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"schema list":         {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"schema plan":         {Kind: kindStream, DB: dbNone, Shape: noShape("a JSON Schema document")},
	"schema storage":      {Kind: kindRead, DB: dbRead, Shape: rowsShape()},
	"scope":               {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"scope add":           {Kind: kindMutation, DB: dbNone},
	"scope check":         {Kind: kindRead, DB: dbNone, Shape: objectShape()},
	"scope rm":            {Kind: kindMutation, DB: dbNone},
	"scope set":           {Kind: kindMutation, DB: dbNone},
	"scope view":          {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"server":              {Kind: kindInteractive, DB: dbWrite},
	"server ca":           {Kind: kindInteractive, DB: dbNone},
	"server ca install":   {Kind: kindMutation, DB: dbNone},
	"server ca path":      {Kind: kindRead, DB: dbNone, Shape: noShape("one path")},
	"server ca print":     {Kind: kindRead, DB: dbNone, Shape: noShape("one PEM certificate")},
	"server ca uninstall": {Kind: kindMutation, DB: dbNone},
	"server status":       {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"server stop":         {Kind: kindMutation, DB: dbNone},
	"skills":              {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"skills gen-flags":    {Kind: kindInteractive, DB: dbNone},
	"skills get":          {Kind: kindRead, DB: dbNone, Shape: noShape("skill text")},
	"skills install":      {Kind: kindMutation, DB: dbNone},
	"skills list":         {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"status":              {Kind: kindRead, DB: dbRead, Shape: objectShape()},
	"storage":             {Kind: kindInteractive, DB: dbNone},
	"storage download":    {Kind: kindStream, DB: dbNone, Shape: noShape("object bytes")},
	"storage ls":          {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"storage presign":     {Kind: kindRead, DB: dbNone, Shape: noShape("one URL")},
	"storage results":     {Kind: kindMutation, DB: dbNone},
	"storage rm":          {Kind: kindMutation, DB: dbNone},
	"storage upload":      {Kind: kindMutation, DB: dbNone},
	"strategy":            {Kind: kindRead, DB: dbNone, Shape: rowsShape()},
	"traffic":             {Kind: kindRead, DB: dbRead, Shape: rowsShape().owned().pagedByQuery()},
	"traffic body":        {Kind: kindRead, DB: dbRead, Shape: objectShape()},
	"traffic headers":     {Kind: kindRead, DB: dbRead, Shape: objectShape()},
	"update":              {Kind: kindMutation, DB: dbNone},
	"version":             {Kind: kindRead, DB: dbNone, Shape: objectShape()},
}

// commandTrait is one command's row in commandTraits.
type commandTrait struct {
	Kind         machineKind
	DB           string
	Shape        commandShape
	SendsTraffic bool
}

// Database intents as commandTraits spells them.
const (
	dbRead  = "read"
	dbWrite = "write"
	dbNone  = dbIntentNone
)

// shapeKind says what a command's -j items are, for shaping.
type shapeKind string

const (
	// shapeNone: nothing to narrow (a schema, one code, a byte stream), or a
	// document that is not a read. A read declaring it says why.
	shapeNone shapeKind = "none"
	// shapeRows: a list of rows; --fields, --compact, --max-output-bytes and
	// (unless paging is none) -n/--offset apply.
	shapeRows shapeKind = "rows"
	// shapeObject: one object (or a fixed handful); --fields applies.
	shapeObject shapeKind = "object"
)

// pagingKind says who pages a rows command.
type pagingKind string

const (
	// pagingInMemory: the whole result is built in memory, so -n/--offset are
	// applied to it after the fact (generically unless the command registered
	// them itself).
	pagingInMemory pagingKind = "inMemory"
	// pagingQuery: the command's own query takes -n/--offset.
	pagingQuery pagingKind = "query"
	// pagingNone: no paging; Reason says why.
	pagingNone pagingKind = "none"
)

// commandShape is how a command's -j document can be narrowed.
type commandShape struct {
	Kind shapeKind
	// Vocab is the --fields vocabulary. Nil: the item keys of the command's
	// registered schema (pkg/contract), else the keys of the rows it emits.
	Vocab []string
	// CompactDrop are the bulky item keys --compact removes.
	CompactDrop []string
	Paging      pagingKind
	// Reason explains a shapeNone read or a pagingNone rows command.
	Reason string
	// Own: the command projects its rows itself (rowShaping, the finding and
	// traffic views, the scan document) and registers its own --fields and
	// --compact; generic shaping leaves its items alone.
	Own bool
}

func rowsShape() commandShape {
	return commandShape{Kind: shapeRows, Paging: pagingInMemory}
}

func objectShape() commandShape {
	return commandShape{Kind: shapeObject, Paging: pagingNone, Reason: "one object"}
}

func noShape(reason string) commandShape {
	return commandShape{Kind: shapeNone, Paging: pagingNone, Reason: reason}
}

// scanDocumentShape is the scan document's: it projects its own findings and
// embeds the first -n of them.
var scanDocumentShape = commandShape{
	Kind: shapeRows, Own: true, Paging: pagingNone,
	Reason: "the scan document embeds the first -n findings; page the rest with finding --scan-uuid",
}

func (s commandShape) owned() commandShape        { s.Own = true; return s }
func (s commandShape) pagedByQuery() commandShape { s.Paging = pagingQuery; return s }

func (s commandShape) unpaged(reason string) commandShape {
	s.Paging, s.Reason = pagingNone, reason
	return s
}

func (s commandShape) drop(keys ...string) commandShape {
	s.CompactDrop = append(append([]string(nil), s.CompactDrop...), keys...)
	return s
}

// vocabFrom declares the vocabulary as the JSON keys of the given struct
// types (a command with more than one row shape names each).
func (s commandShape) vocabFrom(vs ...any) commandShape {
	s.Vocab = nil
	for _, v := range vs {
		for _, k := range contract.JSONFieldNames(v) {
			if !containsString(s.Vocab, k) {
				s.Vocab = append(s.Vocab, k)
			}
		}
	}
	return s
}

// generic reports whether shaping is applied by shaping_traits.go rather than
// by the command.
func (s commandShape) generic() bool {
	return !s.Own && (s.Kind == shapeRows || s.Kind == shapeObject)
}

// staticVocab is the vocabulary known before the command runs: the declared
// one, else the registered schema's item keys (variants included). Nil when
// only the emitted rows can tell.
func (s commandShape) staticVocab(path string) []string {
	if s.Vocab != nil {
		return s.Vocab
	}
	c, ok := contract.LookupCommand(path)
	if !ok || c.Item == nil {
		return nil
	}
	vocab := contract.JSONFieldNames(c.Item)
	for _, v := range c.Variants {
		for _, k := range contract.JSONFieldNames(v.Item) {
			if !containsString(vocab, k) {
				vocab = append(vocab, k)
			}
		}
	}
	return vocab
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// The views the rest of the package reads.
var (
	machineKinds         = deriveTrait(func(t commandTrait) (machineKind, bool) { return t.Kind, true })
	dbIntents            = deriveTrait(func(t commandTrait) (string, bool) { return t.DB, true })
	sendsTrafficCommands = deriveTrait(func(t commandTrait) (bool, bool) { return true, t.SendsTraffic })
)

func deriveTrait[V any](f func(commandTrait) (V, bool)) map[string]V {
	out := make(map[string]V, len(commandTraits))
	for path, t := range commandTraits {
		if v, ok := f(t); ok {
			out[path] = v
		}
	}
	return out
}

// jsonKeysOfType lists the JSON keys of a struct type (pointers followed).
func jsonKeysOfType(t reflect.Type) []string {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	return contract.JSONFieldNames(reflect.New(t).Elem().Interface())
}

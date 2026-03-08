package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// TagAttributeValidator corresponds to the Java interface burp.brh.
type TagAttributeValidator interface {
	IsValidForTag(tagName string) bool
	IsValidForAnyTagInSet(tagNames map[string]struct{}) bool
}

/* -------------------------------------------------------------------------- */
// HTMLTagInfoAccessor corresponds to the Java interface burp.dr2.
// Methods are based on usage in edk.java, dz0.java and its own definition in dr2.java.
type HTMLTagInfoAccessor interface {
	IsHTMLTagInfoAccessor() // Marker method, assuming it might be checked by concrete types
	TagName() string        // Corresponds to String a4();
	Attributes() []*htmlparser.HTMLAttribute
	GetAttributeValue(attributeName string) string // Corresponds to String e(String var1);
}

/* -------------------------------------------------------------------------- */
// TagAttributeCompatibilityAssessor corresponds to the Java interface burp.fbt.
type TagAttributeCompatibilityAssessor interface {
	IsCompatible(tagAccessor HTMLTagInfoAccessor) bool // Uses renamed Dr2_g1r
}

/* -------------------------------------------------------------------------- */
type TagSpecificAssessorRegistry struct {
	checkersByTag map[string]TagAttributeCompatibilityAssessor
}

func NewTagSpecificAssessorRegistry() *TagSpecificAssessorRegistry {
	return &TagSpecificAssessorRegistry{
		checkersByTag: make(map[string]TagAttributeCompatibilityAssessor),
	}
}

func (b *TagSpecificAssessorRegistry) GetCheckerForTag(
	tagName string,
) TagAttributeCompatibilityAssessor {
	tagName = strings.ToLower(tagName)
	if fbtVal, ok := b.checkersByTag[tagName]; ok {
		return fbtVal
	}
	return nil
}

func (b *TagSpecificAssessorRegistry) RegisterCheckerForTag(
	tagName string,
	checker TagAttributeCompatibilityAssessor,
) {
	b.checkersByTag[tagName] = checker
}

/* -------------------------------------------------------------------------- */
type CaseInsensitiveStringSetChecker struct {
	items map[string]struct{} // private final Set<String> a;
}

// NewCaseInsensitiveStringSetChecker creates a new Fl0 instance.
// Corresponds to public fl0(Set<String> var1)
func NewCaseInsensitiveStringSetChecker(
	initialItems map[string]struct{},
) *CaseInsensitiveStringSetChecker {
	itemsCopy := make(map[string]struct{})
	for k := range initialItems {
		itemsCopy[k] = struct{}{}
	}
	return &CaseInsensitiveStringSetChecker{items: itemsCopy}
}

// FilterContainedItems corresponds to public Set<String> a(Set<String> var1) in fl0.java
func (f *CaseInsensitiveStringSetChecker) FilterContainedItems(
	itemsToFilter map[string]struct{},
) map[string]struct{} {
	containedItems := make(map[string]struct{})

	for item := range itemsToFilter {
		if f.Contains(item) {
			containedItems[item] = struct{}{}
		}
	}
	return containedItems
}

// Contains corresponds to public boolean a(String var1) in fl0.java
func (f *CaseInsensitiveStringSetChecker) Contains(itemToFind string) bool {
	for existingItem := range f.items {
		if strings.EqualFold(existingItem, itemToFind) {
			return true
		}
	}
	return false
}

/* -------------------------------------------------------------------------- */
type ExclusionTagAttributeValidator struct {
	excludedTags *CaseInsensitiveStringSetChecker // private final fl0 a;
}

// NewExclusionTagAttributeValidator creates a new Dbz instance.
// Corresponds to public dbz(String... var1)
func NewExclusionTagAttributeValidator(excludedTagNames ...string) *ExclusionTagAttributeValidator {
	excludedSet := make(map[string]struct{})
	for _, s := range excludedTagNames {
		excludedSet[s] = struct{}{}
	}
	return &ExclusionTagAttributeValidator{
		excludedTags: NewCaseInsensitiveStringSetChecker(excludedSet),
	}
}

// IsValidForTag corresponds to public boolean a(String var1) in dbz.java
func (d *ExclusionTagAttributeValidator) IsValidForTag(tagName string) bool {
	return !d.excludedTags.Contains(strings.ToLower(tagName))
}

// IsValidForAnyTagInSet corresponds to public boolean a(Set<String> var1) in dbz.java
func (d *ExclusionTagAttributeValidator) IsValidForAnyTagInSet(tagNames map[string]struct{}) bool {
	excludedAndPresentTags := d.excludedTags.FilterContainedItems(tagNames)
	hasNonExcludedTag := len(excludedAndPresentTags) < len(tagNames)
	return hasNonExcludedTag
}

/* -------------------------------------------------------------------------- */
type InclusionTagAttributeValidator struct {
	includedTags *CaseInsensitiveStringSetChecker // private final fl0 a;
}

// NewInclusionTagAttributeValidator creates a new Crs instance.
// Corresponds to public crs(String... var1)
func NewInclusionTagAttributeValidator(includedTagNames ...string) *InclusionTagAttributeValidator {
	includedSet := make(map[string]struct{})
	for _, s := range includedTagNames {
		includedSet[s] = struct{}{}
	}
	return &InclusionTagAttributeValidator{
		includedTags: NewCaseInsensitiveStringSetChecker(includedSet),
	}
}

// IsValidForTag corresponds to public boolean a(String var1) in crs.java
func (c *InclusionTagAttributeValidator) IsValidForTag(tagName string) bool {
	return c.includedTags.Contains(strings.ToLower(tagName))
}

// IsValidForAnyTagInSet corresponds to public boolean a(Set<String> var1) in crs.java
func (c *InclusionTagAttributeValidator) IsValidForAnyTagInSet(tagNames map[string]struct{}) bool {
	includedAndPresentTags := c.includedTags.FilterContainedItems(tagNames)
	return len(includedAndPresentTags) > 0
}

/* -------------------------------------------------------------------------- */
type FocusEventHiddenInputAssessor struct{}

// NewFocusEventHiddenInputAssessor creates a new Edk_g1r instance.
func NewFocusEventHiddenInputAssessor() *FocusEventHiddenInputAssessor {
	return &FocusEventHiddenInputAssessor{}
}

// IsCompatible corresponds to public boolean a(dr2 var1) in edk.java
func (e *FocusEventHiddenInputAssessor) IsCompatible(tagAccessor HTMLTagInfoAccessor) bool {
	if tagAccessor != nil {
		tagName := tagAccessor.TagName()
		typeAttributeValue := tagAccessor.GetAttributeValue("type")
		if strings.EqualFold("input", tagName) && strings.EqualFold("hidden", typeAttributeValue) {
			return false
		}
	}
	return true
}

/* -------------------------------------------------------------------------- */
type MouseOverEventHiddenInputAssessor struct{}

// NewMouseOverEventHiddenInputAssessor creates a new Dz0_g1r instance.
func NewMouseOverEventHiddenInputAssessor() *MouseOverEventHiddenInputAssessor {
	return &MouseOverEventHiddenInputAssessor{}
}

// IsCompatible corresponds to public boolean a(dr2 var1) in dz0.java
func (d *MouseOverEventHiddenInputAssessor) IsCompatible(tagAccessor HTMLTagInfoAccessor) bool {
	if tagAccessor != nil {
		tagName := tagAccessor.TagName()
		typeAttributeValue := tagAccessor.GetAttributeValue("type")
		if strings.EqualFold(tagName, "input") && strings.EqualFold(typeAttributeValue, "hidden") {
			return false
		}
	}
	return true
}

/* -------------------------------------------------------------------------- */
type EventHandlerEligibilityLogic struct {
	validatorsByEvent     map[string]TagAttributeValidator
	compatibilityRegistry *TagSpecificAssessorRegistry
}

func NewEventHandlerEligibilityLogic() *EventHandlerEligibilityLogic {
	checker := &EventHandlerEligibilityLogic{
		validatorsByEvent:     make(map[string]TagAttributeValidator),
		compatibilityRegistry: NewTagSpecificAssessorRegistry(),
	}
	checker.validatorsByEvent["onmouseover"] = NewExclusionTagAttributeValidator(
		"base",
		"bdo",
		"br",
		"head",
		"html",
		"iframe",
		"meta",
		"param",
		"script",
		"style",
		"title",
	)
	checker.validatorsByEvent["onfocus"] = NewInclusionTagAttributeValidator("input")
	commonRestrictedTags := []string{
		"img",
		"object",
		"video",
		"audio",
		"body",
		"frame",
		"frameset",
		"iframe",
		"link",
		"script",
		"style",
	}
	checker.validatorsByEvent["onerror"] = NewInclusionTagAttributeValidator(
		commonRestrictedTags...)
	checker.validatorsByEvent["onload"] = NewInclusionTagAttributeValidator(commonRestrictedTags...)
	checker.compatibilityRegistry.RegisterCheckerForTag(
		"onfocus",
		NewFocusEventHiddenInputAssessor(),
	)
	checker.compatibilityRegistry.RegisterCheckerForTag(
		"onmouseover",
		NewMouseOverEventHiddenInputAssessor(),
	)
	return checker
}

func (g *EventHandlerEligibilityLogic) AreTagsEligibleForEvent(
	tagNames map[string]struct{},
	eventName string,
) bool {
	var3, ok := g.validatorsByEvent[eventName]
	if !ok || var3 == nil {
		return false
	}
	return var3.IsValidForAnyTagInSet(tagNames)
}

func (g *EventHandlerEligibilityLogic) IsTagEligibleForEvent(
	tagName string,
	tagAccessor HTMLTagInfoAccessor,
	eventName string,
) bool {
	if tagName == "" {
		return false
	}
	brhVal, ok := g.validatorsByEvent[eventName]
	if !ok || brhVal == nil {
		return false
	}
	var4 := brhVal.IsValidForTag(tagName)
	if !var4 {
		return false
	}
	fbtVal := g.compatibilityRegistry.GetCheckerForTag(eventName)
	if fbtVal == nil {
		return false
	}
	return fbtVal.IsCompatible(tagAccessor)
}

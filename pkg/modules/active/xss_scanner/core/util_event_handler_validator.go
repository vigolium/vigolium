package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

type TagAttributeValidator interface {
	IsValidForTag(tagName string) bool
	IsValidForAnyTagInSet(tagNames map[string]struct{}) bool
}

/* -------------------------------------------------------------------------- */
type HTMLTagInfoAccessor interface {
	IsHTMLTagInfoAccessor() // Marker method, assuming it might be checked by concrete types
	TagName() string
	Attributes() []*htmlparser.HTMLAttribute
	GetAttributeValue(attributeName string) string
}

/* -------------------------------------------------------------------------- */
type TagAttributeCompatibilityAssessor interface {
	IsCompatible(tagAccessor HTMLTagInfoAccessor) bool
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
	items map[string]struct{}
}

// NewCaseInsensitiveStringSetChecker creates a new CaseInsensitiveStringSetChecker instance.
func NewCaseInsensitiveStringSetChecker(
	initialItems map[string]struct{},
) *CaseInsensitiveStringSetChecker {
	itemsCopy := make(map[string]struct{})
	for k := range initialItems {
		itemsCopy[k] = struct{}{}
	}
	return &CaseInsensitiveStringSetChecker{items: itemsCopy}
}

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
	excludedTags *CaseInsensitiveStringSetChecker
}

// NewExclusionTagAttributeValidator creates a new ExclusionTagAttributeValidator instance.
func NewExclusionTagAttributeValidator(excludedTagNames ...string) *ExclusionTagAttributeValidator {
	excludedSet := make(map[string]struct{})
	for _, s := range excludedTagNames {
		excludedSet[s] = struct{}{}
	}
	return &ExclusionTagAttributeValidator{
		excludedTags: NewCaseInsensitiveStringSetChecker(excludedSet),
	}
}

func (d *ExclusionTagAttributeValidator) IsValidForTag(tagName string) bool {
	return !d.excludedTags.Contains(strings.ToLower(tagName))
}

func (d *ExclusionTagAttributeValidator) IsValidForAnyTagInSet(tagNames map[string]struct{}) bool {
	excludedAndPresentTags := d.excludedTags.FilterContainedItems(tagNames)
	hasNonExcludedTag := len(excludedAndPresentTags) < len(tagNames)
	return hasNonExcludedTag
}

/* -------------------------------------------------------------------------- */
type InclusionTagAttributeValidator struct {
	includedTags *CaseInsensitiveStringSetChecker
}

// NewInclusionTagAttributeValidator creates a new InclusionTagAttributeValidator instance.
func NewInclusionTagAttributeValidator(includedTagNames ...string) *InclusionTagAttributeValidator {
	includedSet := make(map[string]struct{})
	for _, s := range includedTagNames {
		includedSet[s] = struct{}{}
	}
	return &InclusionTagAttributeValidator{
		includedTags: NewCaseInsensitiveStringSetChecker(includedSet),
	}
}

func (c *InclusionTagAttributeValidator) IsValidForTag(tagName string) bool {
	return c.includedTags.Contains(strings.ToLower(tagName))
}

func (c *InclusionTagAttributeValidator) IsValidForAnyTagInSet(tagNames map[string]struct{}) bool {
	includedAndPresentTags := c.includedTags.FilterContainedItems(tagNames)
	return len(includedAndPresentTags) > 0
}

/* -------------------------------------------------------------------------- */
type FocusEventHiddenInputAssessor struct{}

// NewFocusEventHiddenInputAssessor creates a new FocusEventHiddenInputAssessor instance.
func NewFocusEventHiddenInputAssessor() *FocusEventHiddenInputAssessor {
	return &FocusEventHiddenInputAssessor{}
}

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

// NewMouseOverEventHiddenInputAssessor creates a new MouseOverEventHiddenInputAssessor instance.
func NewMouseOverEventHiddenInputAssessor() *MouseOverEventHiddenInputAssessor {
	return &MouseOverEventHiddenInputAssessor{}
}

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

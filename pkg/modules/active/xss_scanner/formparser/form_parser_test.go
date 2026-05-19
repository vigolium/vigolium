package formparser

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// helper function to quickly parse HTML string to []*HTMLElement for tests
func quickParse(htmlStr string) []*htmlparser.HTMLElement {
	elements, err := htmlparser.ParseHTMLElementsSimple([]byte(htmlStr), 0, len(htmlStr), 0)
	if err != nil {
		panic("quickParse failed: " + err.Error())
	}

	return elements
}

func TestExtractFormsInfo_NoForm(t *testing.T) {
	html := `<html><body><p>No form here.</p></body></html>`
	elements := quickParse(html)

	forms := ExtractFormsInfo(nil, elements, []byte(html), func() bool { return false })

	assert.Empty(t, forms, "Should find no forms")
}

func TestExtractFormsInfo_SimpleEmptyForm(t *testing.T) {
	html := `<form action="/submit" method="POST"></form>`
	elements := quickParse(html)
	request, _ := http.NewRequest("GET", "http://localhost/page", nil)

	forms := ExtractFormsInfo(request, elements, []byte(html), func() bool { return false })

	assert.Len(t, forms, 1, "Should find one form")
	if len(forms) == 1 {
		assert.Equal(t, "http://localhost/submit", forms[0].ActionURL)
		assert.Equal(t, "POST", forms[0].Method)
		assert.Equal(t, "application/x-www-form-urlencoded", forms[0].Enctype)
		assert.Empty(t, forms[0].Inputs, "Form should have no inputs")
		assert.NotNil(t, forms[0].FormElement, "FormElement should not be nil")
		if forms[0].FormElement.TagInfo != nil {
			assert.Equal(t, "form", forms[0].FormElement.TagInfo.Name)
		}
	}
}

func TestExtractFormsInfo_InputTypes(t *testing.T) {
	html := `
		<form action="/test">
			<input type="text" name="text_field" value="hello">
			<input type="password" name="pass_field">
			<input type="hidden" name="hidden_field" value="secret">
			<input type="checkbox" name="cb_field" value="cb_val1" checked>
			<input type="radio" name="radio_field" value="radio_val1" checked>
			<input type="submit" name="submit_button" value="Submit Me">
			<input type="button" name="regular_button" value="Click Me">
			<input type="image" name="image_button" src="img.png">
			<input type="file" name="file_upload">
			<input type="number" name="num_field" value="123">
			<input type="email" name="email_field" value="a@b.com">   благоприятно <!-- Should be text type -->
			<input type="tel" name="tel_field">
			<input name="no_type_field" value="default_text">
			<input type="reset" name="reset_btn">
			<input value="no_name_submit" type="submit">
		</form>
	`
	elements := quickParse(html)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)
	forms := ExtractFormsInfo(request, elements, []byte(html), func() bool { return false })

	assert.Len(t, forms, 1, "Should find one form")
	if len(forms) == 1 {
		form := forms[0]
		// Expect 13 inputs (reset and type="button" are skipped, submit without name is included)
		assert.Len(t, form.Inputs, 13, "Incorrect number of inputs found")

		expectedInputs := []struct {
			Name    string
			Value   string
			Type    InputType
			ElemTag string
		}{
			{Name: "text_field", Value: "hello", Type: InputTypeText, ElemTag: "input"},
			{Name: "pass_field", Value: "", Type: InputTypePassword, ElemTag: "input"},
			{Name: "hidden_field", Value: "secret", Type: InputTypeHidden, ElemTag: "input"},
			{Name: "cb_field", Value: "cb_val1", Type: InputTypeCheckbox, ElemTag: "input"},
			{Name: "radio_field", Value: "radio_val1", Type: InputTypeRadio, ElemTag: "input"},
			{Name: "submit_button", Value: "Submit Me", Type: InputTypeSubmit, ElemTag: "input"},
			{
				Name:    "image_button",
				Value:   "",
				Type:    InputTypeImage,
				ElemTag: "input",
			}, // Value for image input is typically not set like this
			{Name: "file_upload", Value: "", Type: InputTypeFile, ElemTag: "input"},
			{Name: "num_field", Value: "123", Type: InputTypeNumber, ElemTag: "input"},
			{
				Name:    "email_field",
				Value:   "a@b.com",
				Type:    InputTypeText,
				ElemTag: "input",
			}, // Fallback to text
			{
				Name:    "tel_field",
				Value:   "",
				Type:    InputTypeText,
				ElemTag: "input",
			}, // Fallback to text
			{Name: "no_type_field", Value: "default_text", Type: InputTypeText, ElemTag: "input"},
			// {Name: "reset_btn", Type: InputTypeNone}, // Reset buttons are not added
			// Input without name but type submit/button/image should be added.
			// In this case, stringToInputType returns InputTypeSubmit for type="submit"
			// The condition for adding is `inputName != "" || finalInputType == InputTypeSubmit || ...`
			// So, a submit button without a name IS added.
			{Name: "", Value: "no_name_submit", Type: InputTypeSubmit, ElemTag: "input"},
		}

		for _, expected := range expectedInputs {
			found := false
			for _, actual := range form.Inputs {
				if actual.Name == expected.Name && actual.Type == expected.Type {
					assert.Equal(
						t,
						expected.Value,
						actual.Value,
						"Value mismatch for input %s",
						expected.Name,
					)
					assert.NotNil(t, actual.InputElement)
					if actual.InputElement.TagInfo != nil {
						assert.Equal(t, expected.ElemTag, actual.InputElement.TagInfo.Name)
					}
					found = true
					break
				}
			}
			assert.True(
				t,
				found,
				"Expected input not found: Name='%s', Type=%d",
				expected.Name,
				expected.Type,
			)
		}
	}
}

func TestExtractFormsInfo_FormAttributesAndBaseHref(t *testing.T) {
	tests := []struct {
		name            string
		html            string
		basePageURL     string
		expectedAction  string
		expectedMethod  string
		expectedEnctype string
	}{
		{
			name:            "Simple attributes",
			html:            `<form action="/go" method="post" enctype="multipart/form-data"><input name="t"></form>`,
			basePageURL:     "http://example.com/page/",
			expectedAction:  "http://example.com/go",
			expectedMethod:  "POST",
			expectedEnctype: "multipart/form-data",
		},
		{
			name:            "Default attributes",
			html:            `<form><input name="t"></form>`,
			basePageURL:     "http://example.com/page/",
			expectedAction:  "http://example.com/page/", // Action defaults to current page URL
			expectedMethod:  "GET",
			expectedEnctype: "application/x-www-form-urlencoded",
		},
		{
			name:            "Action with base href",
			html:            `<html><head><base href="http://api.example.com/v1/"></head><body><form action="users"><input name="t"></form></body></html>`,
			basePageURL:     "http://example.com/page/", // This base URL will be overridden by <base>
			expectedAction:  "http://api.example.com/v1/users",
			expectedMethod:  "GET",
			expectedEnctype: "application/x-www-form-urlencoded",
		},
		{
			name:            "Action with different base href path",
			html:            `<html><head><base href="/basepath/"></head><body><form action="submit"><input name="t"></form></body></html>`,
			basePageURL:     "http://example.com/page/",
			expectedAction:  "http://example.com/basepath/submit",
			expectedMethod:  "GET",
			expectedEnctype: "application/x-www-form-urlencoded",
		},
		{
			name:            "Empty action with base href",
			html:            `<html><head><base href="http://api.example.com/v1/"></head><body><form action=""><input name="t"></form></body></html>`,
			basePageURL:     "http://example.com/page/",
			expectedAction:  "http://api.example.com/v1/", // Action resolves to base
			expectedMethod:  "GET",
			expectedEnctype: "application/x-www-form-urlencoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elements := quickParse(tt.html)
			parsedBaseURL, _ := url.Parse(tt.basePageURL)
			request := &http.Request{URL: parsedBaseURL}

			forms := ExtractFormsInfo(
				request,
				elements,
				[]byte(tt.html),
				func() bool { return false },
			)
			assert.Len(t, forms, 1)
			if len(forms) == 1 {
				assert.Equal(t, tt.expectedAction, forms[0].ActionURL, "ActionURL mismatch")
				assert.Equal(t, tt.expectedMethod, forms[0].Method, "Method mismatch")
				assert.Equal(t, tt.expectedEnctype, forms[0].Enctype, "Enctype mismatch")
			}
		})
	}
}

func TestExtractFormsInfo_Textarea(t *testing.T) {
	html := `
		<form action="/submit_area">
			<textarea name="myarea">This is the first line.
This is the second line with <b>bold</b> text and an <img src="test.png"/> tag.</textarea>
			<textarea name="emptyarea"></textarea>
			<textarea name="area_before_form_end">Content</textarea>
		</form>
		<form><textarea name="area_interrupt_by_form_close">Line1</form>Line2</textarea>
	`
	// For the last textarea, "Line2</textarea>" will be outside the form and not parsed as its content.

	elements := quickParse(html)
	originalBytes := []byte(html)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)
	forms := ExtractFormsInfo(request, elements, originalBytes, func() bool { return false })

	assert.Len(t, forms, 2, "Should find two forms")

	if len(forms) >= 1 {
		form1 := forms[0]
		assert.Len(t, form1.Inputs, 3, "Form 1 should have 3 textareas")

		// myarea
		foundMyArea := false
		for _, input := range form1.Inputs {
			if input.Name == "myarea" {
				assert.Equal(t, InputTypeTextarea, input.Type)
				// Expected value includes the HTML tags as raw strings
				expectedValue := "This is the first line.\nThis is the second line with<b>bold</b>text and an<img src=\"test.png\"/>tag."
				// Normalize whitespace for comparison, as TrimSpace was used for TextNodes
				assert.Equal(
					t,
					strings.Join(strings.Fields(expectedValue), " "),
					strings.Join(strings.Fields(input.Value), " "),
				)
				foundMyArea = true
				break
			}
		}
		assert.True(t, foundMyArea, "Textarea 'myarea' not found or content mismatch")

		// emptyarea
		foundEmptyArea := false
		for _, input := range form1.Inputs {
			if input.Name == "emptyarea" {
				assert.Equal(t, InputTypeTextarea, input.Type)
				assert.Equal(t, "", input.Value)
				foundEmptyArea = true
				break
			}
		}
		assert.True(t, foundEmptyArea, "Textarea 'emptyarea' not found")

		// area_before_form_end
		foundAreaBeforeEnd := false
		for _, input := range form1.Inputs {
			if input.Name == "area_before_form_end" {
				assert.Equal(t, InputTypeTextarea, input.Type)
				assert.Equal(t, "Content", input.Value)
				foundAreaBeforeEnd = true
				break
			}
		}
		assert.True(t, foundAreaBeforeEnd, "Textarea 'area_before_form_end' not found")
	}

	if len(forms) >= 2 {
		form2 := forms[1]
		assert.Len(t, form2.Inputs, 1, "Form 2 should have 1 textarea")
		if len(form2.Inputs) == 1 {
			input := form2.Inputs[0]
			assert.Equal(t, "area_interrupt_by_form_close", input.Name)
			assert.Equal(t, InputTypeTextarea, input.Type)
			assert.Equal(t, "Line1", input.Value, "Textarea should be interrupted by form close")
		}
	}
}

func TestExtractFormsInfo_SelectOptions(t *testing.T) {
	html := `
		<form method="post">
			<select name="single_select">
				<option value="val1">Opt1</option>
				<option>Opt2 Value From Text</option>
				<option value="val3" selected>Opt3</option>
				<option value=""></option> <!-- Empty value attribute -->
				<option>  </option> <!-- Text content is whitespace -->
			</select>
			<select name="multi_select" multiple>
				<option value="mval1">MultiOpt1</option>
				<option value="mval2">MultiOpt2</option>
			</select>
			<select name="empty_select"></select>
			<select name="select_before_form_end">
			    <option value="last_opt">Last Option</option>
            </select>
		</form>
		<form name="form2">
		    <select name="select_interrupt_by_form_close">
		        <option value="opt_form2">Option Form 2</option>
		    </form>
		    <option value="after_form_close">This option is outside</option>
        </select> 
	`
	elements := quickParse(html)
	originalBytes := []byte(html)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)
	forms := ExtractFormsInfo(request, elements, originalBytes, func() bool { return false })

	assert.Len(t, forms, 2, "Should find two forms")

	if len(forms) >= 1 {
		form1 := forms[0]
		// Expected inputs:
		// For single_select: 5 options become 5 inputs
		// For multi_select: 2 options become 2 inputs
		// For empty_select: 0 options
		// For select_before_form_end: 1 option
		// Total = 5 + 2 + 0 + 1 = 8.
		// The select tags themselves are not added as FormInputInfo if we only add options.
		// Let's verify the current behavior of ExtractFormsInfo which might add the select tag as well.
		// Current ExtractFormsInfo adds FormInputInfo for each OPTION.

		var singleSelectOptions []*FormInputInfo
		var multiSelectOptions []*FormInputInfo
		var emptySelectOptions []*FormInputInfo
		var selectBeforeFormEndOptions []*FormInputInfo

		for _, inp := range form1.Inputs {
			switch inp.Name {
			case "single_select":
				singleSelectOptions = append(singleSelectOptions, inp)
			case "multi_select":
				multiSelectOptions = append(multiSelectOptions, inp)
			case "empty_select":
				emptySelectOptions = append(emptySelectOptions, inp)
			case "select_before_form_end":
				selectBeforeFormEndOptions = append(selectBeforeFormEndOptions, inp)
			}
		}

		assert.Len(t, singleSelectOptions, 5, "single_select should have 5 options as inputs")
		assert.Equal(t, "val1", singleSelectOptions[0].Value)
		assert.Equal(t, "Opt2 Value From Text", singleSelectOptions[1].Value)
		assert.Equal(t, "val3", singleSelectOptions[2].Value)
		assert.Equal(t, "", singleSelectOptions[3].Value) // Empty value attr
		assert.Equal(
			t,
			"",
			singleSelectOptions[4].Value,
		) // Whitespace text content trimmed to empty
		for _, opt := range singleSelectOptions {
			assert.Equal(t, InputTypeSelect, opt.Type)
		}

		assert.Len(t, multiSelectOptions, 2, "multi_select should have 2 options as inputs")
		assert.Equal(t, "mval1", multiSelectOptions[0].Value)
		assert.Equal(t, "mval2", multiSelectOptions[1].Value)
		for _, opt := range multiSelectOptions {
			assert.Equal(t, InputTypeSelectMultiple, opt.Type)
		}

		assert.Len(t, emptySelectOptions, 0, "empty_select should have 0 options as inputs")

		assert.Len(t, selectBeforeFormEndOptions, 1, "select_before_form_end should have 1 option")
		if len(selectBeforeFormEndOptions) == 1 {
			assert.Equal(t, "last_opt", selectBeforeFormEndOptions[0].Value)
		}
	}

	if len(forms) >= 2 {
		form2 := forms[1]
		assert.Len(t, form2.Inputs, 1, "Form 2 (interrupted select) should have 1 option as input")
		if len(form2.Inputs) == 1 {
			input := form2.Inputs[0]
			assert.Equal(t, "select_interrupt_by_form_close", input.Name)
			assert.Equal(t, InputTypeSelect, input.Type)
			assert.Equal(t, "opt_form2", input.Value)
		}
	}
}

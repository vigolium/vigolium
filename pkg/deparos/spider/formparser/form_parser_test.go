package formparser

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/html"
)

// helper function to quickly parse HTML string to *html.Node for tests
func quickParse(htmlStr string) *html.Node {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		panic("quickParse failed: " + err.Error())
	}
	return doc
}

func TestExtractFormsInfo_NoForm(t *testing.T) {
	htmlStr := `<html><body><p>No form here.</p></body></html>`
	doc := quickParse(htmlStr)

	forms := ExtractFormsInfo(nil, doc, func() bool { return false })

	assert.Empty(t, forms, "Should find no forms")
}

func TestExtractFormsInfo_SimpleEmptyForm(t *testing.T) {
	htmlStr := `<form action="/submit" method="POST"></form>`
	doc := quickParse(htmlStr)
	request, _ := http.NewRequest("GET", "http://localhost/page", nil)

	forms := ExtractFormsInfo(request, doc, func() bool { return false })

	assert.Len(t, forms, 1, "Should find one form")
	if len(forms) == 1 {
		assert.Equal(t, "http://localhost/submit", forms[0].ActionURL)
		assert.Equal(t, "POST", forms[0].Method)
		assert.Equal(t, "application/x-www-form-urlencoded", forms[0].Enctype)
		assert.Empty(t, forms[0].Inputs, "Form should have no inputs")
		assert.NotNil(t, forms[0].FormElement, "FormElement should not be nil")
		assert.Equal(t, "form", forms[0].FormElement.Data)
	}
}

func TestExtractFormsInfo_InputTypes(t *testing.T) {
	htmlStr := `
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
			<input type="email" name="email_field" value="a@b.com">
			<input type="tel" name="tel_field">
			<input name="no_type_field" value="default_text">
			<input type="reset" name="reset_btn">
			<input value="no_name_submit" type="submit">
		</form>
	`
	doc := quickParse(htmlStr)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)
	forms := ExtractFormsInfo(request, doc, func() bool { return false })

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
			},
			{Name: "file_upload", Value: "", Type: InputTypeFile, ElemTag: "input"},
			{Name: "num_field", Value: "123", Type: InputTypeNumber, ElemTag: "input"},
			{
				Name:    "email_field",
				Value:   "a@b.com",
				Type:    InputTypeText,
				ElemTag: "input",
			},
			{
				Name:    "tel_field",
				Value:   "",
				Type:    InputTypeText,
				ElemTag: "input",
			},
			{Name: "no_type_field", Value: "default_text", Type: InputTypeText, ElemTag: "input"},
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
					assert.Equal(t, expected.ElemTag, actual.InputElement.Data)
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
			expectedAction:  "http://example.com/page/",
			expectedMethod:  "GET",
			expectedEnctype: "application/x-www-form-urlencoded",
		},
		{
			name:            "Action with base href",
			html:            `<html><head><base href="http://api.example.com/v1/"></head><body><form action="users"><input name="t"></form></body></html>`,
			basePageURL:     "http://example.com/page/",
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
			expectedAction:  "http://api.example.com/v1/",
			expectedMethod:  "GET",
			expectedEnctype: "application/x-www-form-urlencoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := quickParse(tt.html)
			parsedBaseURL, _ := url.Parse(tt.basePageURL)
			request := &http.Request{URL: parsedBaseURL}

			forms := ExtractFormsInfo(
				request,
				doc,
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
	htmlStr := `
		<form action="/submit_area">
			<textarea name="myarea">This is the first line.
This is the second line with <b>bold</b> text and an <img src="test.png"/> tag.</textarea>
			<textarea name="emptyarea"></textarea>
			<textarea name="area_before_form_end">Content</textarea>
		</form>
	`

	doc := quickParse(htmlStr)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)
	forms := ExtractFormsInfo(request, doc, func() bool { return false })

	assert.Len(t, forms, 1, "Should find one form")

	if len(forms) >= 1 {
		form1 := forms[0]
		assert.Len(t, form1.Inputs, 3, "Form 1 should have 3 textareas")

		// myarea
		foundMyArea := false
		for _, input := range form1.Inputs {
			if input.Name == "myarea" {
				assert.Equal(t, InputTypeTextarea, input.Type)
				// html.Render preserves whitespace around HTML tags
				assert.Contains(t, input.Value, "first line")
				assert.Contains(t, input.Value, "second line")
				assert.Contains(t, input.Value, "<b>bold</b>")
				foundMyArea = true
				break
			}
		}
		assert.True(t, foundMyArea, "Textarea 'myarea' not found")

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
}

func TestExtractFormsInfo_SelectOptions(t *testing.T) {
	htmlStr := `
		<form method="post">
			<select name="single_select">
				<option value="val1">Opt1</option>
				<option>Opt2 Value From Text</option>
				<option value="val3" selected>Opt3</option>
				<option value=""></option>
				<option>  </option>
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
	`
	doc := quickParse(htmlStr)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)
	forms := ExtractFormsInfo(request, doc, func() bool { return false })

	assert.Len(t, forms, 1, "Should find one form")

	if len(forms) >= 1 {
		form1 := forms[0]

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
		if len(singleSelectOptions) >= 5 {
			assert.Equal(t, "val1", singleSelectOptions[0].Value)
			assert.Equal(t, "Opt2 Value From Text", singleSelectOptions[1].Value)
			assert.Equal(t, "val3", singleSelectOptions[2].Value)
			assert.Equal(t, "", singleSelectOptions[3].Value)
			assert.Equal(t, "", singleSelectOptions[4].Value)
			for _, opt := range singleSelectOptions {
				assert.Equal(t, InputTypeSelect, opt.Type)
			}
		}

		assert.Len(t, multiSelectOptions, 2, "multi_select should have 2 options as inputs")
		if len(multiSelectOptions) >= 2 {
			assert.Equal(t, "mval1", multiSelectOptions[0].Value)
			assert.Equal(t, "mval2", multiSelectOptions[1].Value)
			for _, opt := range multiSelectOptions {
				assert.Equal(t, InputTypeSelectMultiple, opt.Type)
			}
		}

		assert.Len(t, emptySelectOptions, 0, "empty_select should have 0 options as inputs")

		assert.Len(t, selectBeforeFormEndOptions, 1, "select_before_form_end should have 1 option")
		if len(selectBeforeFormEndOptions) == 1 {
			assert.Equal(t, "last_opt", selectBeforeFormEndOptions[0].Value)
		}
	}
}

func TestExtractFormsInfo_ButtonElement(t *testing.T) {
	htmlStr := `
		<form action="/btn_test">
			<button type="submit" name="submit_btn" value="submit_val">Submit</button>
			<button type="reset" name="reset_btn">Reset</button>
			<button type="button" name="button_btn">Just Button</button>
			<button name="default_btn" value="default_val">Default Type (Submit)</button>
		</form>
	`
	doc := quickParse(htmlStr)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)
	forms := ExtractFormsInfo(request, doc, func() bool { return false })

	assert.Len(t, forms, 1)
	if len(forms) == 1 {
		form := forms[0]
		// Only submit buttons should be added
		assert.Len(t, form.Inputs, 2, "Should have 2 submit buttons")

		foundSubmitBtn := false
		foundDefaultBtn := false
		for _, inp := range form.Inputs {
			if inp.Name == "submit_btn" {
				assert.Equal(t, InputTypeSubmit, inp.Type)
				assert.Equal(t, "submit_val", inp.Value)
				foundSubmitBtn = true
			}
			if inp.Name == "default_btn" {
				assert.Equal(t, InputTypeSubmit, inp.Type)
				assert.Equal(t, "default_val", inp.Value)
				foundDefaultBtn = true
			}
		}
		assert.True(t, foundSubmitBtn, "Submit button not found")
		assert.True(t, foundDefaultBtn, "Default type button (submit) not found")
	}
}

func TestExtractFormsInfo_MultipleForms(t *testing.T) {
	htmlStr := `
		<html>
		<body>
			<form id="form1" action="/action1" method="GET">
				<input name="f1_input" value="v1">
			</form>
			<div>
				<form id="form2" action="/action2" method="POST">
					<input name="f2_input" value="v2">
				</form>
			</div>
			<form id="form3">
				<input name="f3_input" value="v3">
			</form>
		</body>
		</html>
	`
	doc := quickParse(htmlStr)
	request, _ := http.NewRequest("GET", "http://localhost/page", nil)
	forms := ExtractFormsInfo(request, doc, func() bool { return false })

	assert.Len(t, forms, 3, "Should find 3 forms")

	if len(forms) >= 3 {
		assert.Equal(t, "http://localhost/action1", forms[0].ActionURL)
		assert.Equal(t, "GET", forms[0].Method)
		assert.Len(t, forms[0].Inputs, 1)
		if len(forms[0].Inputs) > 0 {
			assert.Equal(t, "f1_input", forms[0].Inputs[0].Name)
		}

		assert.Equal(t, "http://localhost/action2", forms[1].ActionURL)
		assert.Equal(t, "POST", forms[1].Method)
		assert.Len(t, forms[1].Inputs, 1)
		if len(forms[1].Inputs) > 0 {
			assert.Equal(t, "f2_input", forms[1].Inputs[0].Name)
		}

		assert.Equal(t, "http://localhost/page", forms[2].ActionURL)
		assert.Equal(t, "GET", forms[2].Method)
		assert.Len(t, forms[2].Inputs, 1)
		if len(forms[2].Inputs) > 0 {
			assert.Equal(t, "f3_input", forms[2].Inputs[0].Name)
		}
	}
}

func TestExtractFormsInfo_StopSupplier(t *testing.T) {
	htmlStr := `
		<form action="/form1"><input name="i1"></form>
		<form action="/form2"><input name="i2"></form>
		<form action="/form3"><input name="i3"></form>
	`
	doc := quickParse(htmlStr)
	request, _ := http.NewRequest("GET", "http://localhost/", nil)

	callCount := 0
	forms := ExtractFormsInfo(request, doc, func() bool {
		callCount++
		return callCount > 1 // Stop after processing first form
	})

	// Should return nil when stop is triggered
	assert.Nil(t, forms, "Should return nil when stop supplier returns true")
}

func TestExtractFormsInfo_NilDoc(t *testing.T) {
	forms := ExtractFormsInfo(nil, nil, func() bool { return false })
	assert.Nil(t, forms, "Should return nil for nil doc")
}

func TestExtractFormsInfo_NilRequest(t *testing.T) {
	htmlStr := `<form action="http://absolute.com/path"><input name="i"></form>`
	doc := quickParse(htmlStr)

	forms := ExtractFormsInfo(nil, doc, func() bool { return false })

	assert.Len(t, forms, 1)
	if len(forms) == 1 {
		assert.Equal(t, "http://absolute.com/path", forms[0].ActionURL)
	}
}

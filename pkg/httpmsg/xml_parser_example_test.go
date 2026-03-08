package httpmsg_test

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func ExampleParseXMLBody() {
	request := []byte(`POST /api HTTP/1.1
Host: example.com
Content-Type: application/xml

<user>
  <name>John</name>
  <age>30</age>
</user>`)

	// Find body offset
	bodyOffset := httpmsg.FindBodyOffset(request)

	// Parse XML parameters
	params, err := httpmsg.ParseXMLBody(request, bodyOffset)
	if err != nil {
		panic(err)
	}

	// Print extracted parameters
	for _, p := range params {
		fmt.Printf("%s: %s = %s\n",
			p.Type(),
			p.Name(),
			p.Value())
	}

	// Output:
	// XML_PARAM: name = John
	// XML_PARAM: age = 30
}

func ExampleParseXMLBody_withAttributes() {
	request := []byte(`POST /api HTTP/1.1
Host: example.com
Content-Type: application/xml

<user id="123" role="admin">
  <name>John</name>
</user>`)

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseXMLBody(request, bodyOffset)

	// Print attributes and elements separately
	fmt.Println("Attributes:")
	for _, p := range params {
		if p.Type() == httpmsg.ParamXMLAttr {
			fmt.Printf("  %s = %s\n", p.Name(), p.Value())
		}
	}

	fmt.Println("Elements:")
	for _, p := range params {
		if p.Type() == httpmsg.ParamXML {
			fmt.Printf("  %s = %s\n", p.Name(), p.Value())
		}
	}

	// Output:
	// Attributes:
	//   user@id = 123
	//   user@role = admin
	// Elements:
	//   name = John
}

func ExampleParseXMLBody_soap() {
	// Example SOAP request
	request := []byte(`POST /soap/endpoint HTTP/1.1
Host: api.example.com
Content-Type: application/xml

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <UserId>12345</UserId>
      <IncludeDetails>true</IncludeDetails>
    </GetUser>
  </soap:Body>
</soap:Envelope>`)

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseXMLBody(request, bodyOffset)

	// Print all text elements
	for _, p := range params {
		if p.Type() == httpmsg.ParamXML {
			fmt.Printf("%s = %s\n", p.Name(), p.Value())
		}
	}

	// Output:
	// userid = 12345
	// includedetails = true
}

func ExampleParseXMLBody_offsets() {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<user id="123">
  <name>John</name>
</user>`)

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseXMLBody(request, bodyOffset)

	// Show parameter offsets
	for _, p := range params {
		fmt.Printf("%s '%s':\n", p.Type(), p.Name())
		fmt.Printf("  Value: '%s'\n", p.Value())
		fmt.Printf("  ValueStart: %d, ValueEnd: %d\n", p.ValueStart(), p.ValueEnd())

		// Extract actual value from request using offsets
		actualValue := string(request[p.ValueStart():p.ValueEnd()])
		fmt.Printf("  Extracted: '%s'\n", actualValue)
	}

	// Output:
	// XML_ATTR 'user@id':
	//   Value: '123'
	//   ValueStart: 57, ValueEnd: 60
	//   Extracted: '123'
	// XML_PARAM 'name':
	//   Value: 'John'
	//   ValueStart: 71, ValueEnd: 75
	//   Extracted: 'John'
}

func ExampleParseXMLBody_selfClosing() {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<config>
  <option name="debug" value="true"/>
  <option name="verbose" value="false"/>
</config>`)

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseXMLBody(request, bodyOffset)

	// Self-closing tags only have attributes
	for _, p := range params {
		if p.Type() == httpmsg.ParamXMLAttr {
			fmt.Printf("%s = %s\n", p.Name(), p.Value())
		}
	}

	// Output:
	// option@name = debug
	// option@value = true
	// option@name = verbose
	// option@value = false
}

func ExampleParseXMLBody_nested() {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<company>
  <department id="IT">
    <employee>
      <name>John Doe</name>
      <position>Developer</position>
    </employee>
  </department>
</company>`)

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseXMLBody(request, bodyOffset)

	// Print all parameters
	for _, p := range params {
		fmt.Printf("%s: %s = %s\n",
			p.Type(),
			p.Name(),
			p.Value())
	}

	// Output:
	// XML_ATTR: department@id = it
	// XML_PARAM: name = John Doe
	// XML_PARAM: position = Developer
}

func ExampleParseXMLBody_emptyAndWhitespace() {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <empty></empty>
  <whitespace>   </whitespace>
  <content>data</content>
</root>`)

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseXMLBody(request, bodyOffset)

	// Only non-empty text content is extracted
	for _, p := range params {
		if p.Type() == httpmsg.ParamXML {
			fmt.Printf("%s = '%s'\n", p.Name(), p.Value())
		}
	}

	// Output:
	// content = 'data'
}

func ExampleParseXMLBody_realWorldAPI() {
	// Real-world API request example
	request := []byte(`POST /api/v1/users HTTP/1.1
Host: api.example.com
Content-Type: application/xml
Authorization: Bearer token123

<?xml version="1.0" encoding="UTF-8"?>
<UserRequest xmlns="http://example.com/api/v1" version="1.0">
  <Authentication token="abc123" timestamp="2024-01-01T00:00:00Z"/>
  <UserData>
    <Username>admin</Username>
    <Email>admin@example.com</Email>
    <Preferences theme="dark" notifications="enabled"/>
  </UserData>
</UserRequest>`)

	bodyOffset := httpmsg.FindBodyOffset(request)
	params, _ := httpmsg.ParseXMLBody(request, bodyOffset)

	fmt.Printf("Total parameters extracted: %d\n\n", len(params))

	// Group by type
	attrCount := 0
	elemCount := 0
	for _, p := range params {
		switch p.Type() {
		case httpmsg.ParamXMLAttr:
			attrCount++
		case httpmsg.ParamXML:
			elemCount++
		}
	}

	fmt.Printf("Attributes: %d\n", attrCount)
	fmt.Printf("Elements: %d\n", elemCount)

	// Output:
	// Total parameters extracted: 8
	//
	// Attributes: 6
	// Elements: 2
}

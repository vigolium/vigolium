package lfi_generic

import (
	"regexp"
	"strings"
)

var topParams = []string{
	"cat",
	"dir",
	"action",
	"board",
	"date",
	"detail",
	"file",
	"download",
	"path",
	"folder",
	"prefix",
	"include",
	"page",
	"inc",
	"locate",
	"show",
	"doc",
	"site",
	"type",
	"view",
	"content",
	"document",
	"layout",
	"mod",
	"conf",
	"url",
	"img",
	"image",
	"images",
}

var topParamRegexes = []*regexp.Regexp{
	regexp.MustCompile("(?i)(.*file.*)"),
	regexp.MustCompile("(?i)(.*dir.*)"),
	regexp.MustCompile("(?i)(.*download.*)"),
	regexp.MustCompile("(?i)(.*path.*)"),
	regexp.MustCompile("(?i)(.*folder.*)"),
	regexp.MustCompile("(?i)(.*page.*)"),
	regexp.MustCompile("(?i)(.*url.*)"),
}

func matchTopParams(str string) bool {
	for _, param := range topParams {
		if strings.Contains(str, param) {
			return true
		}
	}
	for _, param := range topParamRegexes {
		if param.MatchString(str) {
			return true
		}
	}
	return false
}

var mayBePathRegex = regexp.MustCompile(
	`(?i)(^(./|../|/)|(.html|.htm|.xml|.conf|.cfg|.log|.txt|.pdf|.doc|.docx|.xls|.csv|.png|.jpg|.gif|.jpeg)$)`,
)

func maybePath(str string) bool {
	return mayBePathRegex.MatchString(str)
}

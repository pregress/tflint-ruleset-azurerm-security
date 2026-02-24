package project

import "fmt"

// Version is ruleset version
const Version string = "0.1.14"

// ReferenceLink returns the rule reference link
func ReferenceLink(name string) string {
	return fmt.Sprintf("https://github.com/pregress/tflint-ruleset-azurerm-security/blob/v%s/docs/rules/%s.md", Version, name)
}

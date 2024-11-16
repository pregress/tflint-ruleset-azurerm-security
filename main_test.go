// main_test.go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRulesLength(t *testing.T) {
	ruleSet := createRuleSet()
	actualRules := len(ruleSet.Rules)

	// Count .go files in rules directory that don't end with _test.go
	rulesPath := "./rules"
	expectedRules := 0

	err := filepath.Walk(rulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && 
		   strings.HasSuffix(path, ".go") && 
		   !strings.HasSuffix(path, "_test.go") {
			expectedRules++
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Error walking rules directory: %v", err)
	}

	if actualRules != expectedRules {
		t.Errorf("Number of rules does not match number of rule files. Got %d rules, expected %d", 
			actualRules, expectedRules)
	}
}

func TestRuleLinks(t *testing.T) {
	ruleSet := createRuleSet()
	
	for _, rule := range ruleSet.Rules {
		link := rule.Link()
		if link == "" {
			t.Errorf("Rule %T has an empty Link() return value", rule)
		}
	}
}

func TestRuleDocumentation(t *testing.T) {
	ruleSet := createRuleSet()
	docsDir := "./docs/rules"
	templatePath := filepath.Join(docsDir, "template.md")

	// Ensure docs directory exists
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		t.Fatalf("Failed to create docs directory: %v", err)
	}

	// Read template file
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("Failed to read template file: %v", err)
	}

	for _, rule := range ruleSet.Rules {
		ruleName := rule.Name()
		docPath := filepath.Join(docsDir, ruleName+".md")

		// Check if documentation file exists
		fileInfo, err := os.Stat(docPath)
		if os.IsNotExist(err) {
			// Get resource type using reflection
			ruleValue := reflect.ValueOf(rule)
			resourceTypeField := ruleValue.Elem().FieldByName("resourceType")
			
			if !resourceTypeField.IsValid() {
				t.Errorf("Rule %s does not have a resourceType field", ruleName)
				continue
			}
			
			resourceType := resourceTypeField.String()
			
			// Prepare the content with replacements
			content := string(templateContent)
			replacements := map[string]string{
				"{{rule_name}}": ruleName,
				"{{severity}}": rule.Severity().String(),
				"{{resource_name}}": resourceType,
			}
			
			for placeholder, value := range replacements {
				content = strings.ReplaceAll(content, placeholder, value)
			}

			// Create documentation file with replaced content
			err = os.WriteFile(docPath, []byte(content), 0644)
			if err != nil {
				t.Errorf("Failed to create documentation file for rule %s: %v", ruleName, err)
				continue
			}

			// Verify the replacements were made correctly
			createdContent, err := os.ReadFile(docPath)
			if err != nil {
				t.Errorf("Failed to read created documentation file for rule %s: %v", ruleName, err)
				continue
			}

			// Check if any placeholders remain
			for placeholder := range replacements {
				if bytes.Contains(createdContent, []byte(placeholder)) {
					t.Errorf("Documentation file for rule %s still contains placeholder %s", ruleName, placeholder)
				}
			}
		} else if err != nil {
			t.Errorf("Error checking documentation file for rule %s: %v", ruleName, err)
			continue
		} else {
			// File exists, check for TODO markers
			content, err := os.ReadFile(docPath)
			if err != nil {
				t.Errorf("Failed to read existing documentation file for rule %s: %v", ruleName, err)
				continue
			}

			contentStr := string(content)
			if strings.Contains(contentStr, "TODO") {
				t.Errorf("Documentation file for rule %s still contains TODO markers. This indicates incomplete documentation", ruleName)
				
				// Optional: Print the lines containing TODO for easier identification
				lines := strings.Split(contentStr, "\n")
				for i, line := range lines {
					if strings.Contains(line, "TODO") {
						t.Errorf("  Line %d: %s", i+1, line)
					}
				}
			}

			// Also verify the file is not empty
			if fileInfo.Size() == 0 {
				t.Errorf("Documentation file for rule %s exists but is empty", ruleName)
			}
		}
	}
}
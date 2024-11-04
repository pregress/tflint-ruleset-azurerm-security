// main_test.go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesLength(t *testing.T) {
	ruleSet := CreateRuleSet()
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
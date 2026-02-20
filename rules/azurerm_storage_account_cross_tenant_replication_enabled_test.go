package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermStorageAccountCrossTenantReplicationEnabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "cross_tenant_replication_enabled is not defined",
			Content: `
resource "azurerm_storage_account" "example" {
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "cross_tenant_replication_enabled is true",
			Content: `
resource "azurerm_storage_account" "example" {
  cross_tenant_replication_enabled  = true
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountCrossTenantReplicationEnabled(),
					Message: "cross_tenant_replication_enabled should be false",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 39},
						End:      hcl.Pos{Line: 3, Column: 43},
					},
				},
			},
		},
		{
			Name: "cross_tenant_replication_enabled is false",
			Content: `
resource "azurerm_storage_account" "example" {
  cross_tenant_replication_enabled  = false
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple storage accounts with mixed settings",
			Content: `
resource "azurerm_storage_account" "example1" {
  cross_tenant_replication_enabled  = false
}

resource "azurerm_storage_account" "example2" {
  cross_tenant_replication_enabled  = true
}

resource "azurerm_storage_account" "example3" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountCrossTenantReplicationEnabled(),
					Message: "cross_tenant_replication_enabled should be false",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 7, Column: 39},
						End:      hcl.Pos{Line: 7, Column: 43},
					},
				},
			},
		},
	}

	rule := NewAzurermStorageAccountCrossTenantReplicationEnabled()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}

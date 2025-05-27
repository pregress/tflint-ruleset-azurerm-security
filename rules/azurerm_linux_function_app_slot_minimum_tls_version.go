package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermLinuxFunctionAppSlotMinimumTLSVersion checks that minimum_tls_version is set to "1.2" or "1.3"
type AzurermLinuxFunctionAppSlotMinimumTLSVersion struct {
	tflint.DefaultRule

	resourceType  string
	attributePath []string
	versions      []string
}

// NewAzurermLinuxFunctionAppSlotMinimumTLSVersion returns a new rule instance
func NewAzurermLinuxFunctionAppSlotMinimumTLSVersion() *AzurermLinuxFunctionAppSlotMinimumTLSVersion {
	return &AzurermLinuxFunctionAppSlotMinimumTLSVersion{
		resourceType:  "azurerm_linux_function_app_slot",
		attributePath: []string{"site_config", "minimum_tls_version"},
		versions:      []string{"1.2", "1.3"},
	}
}

// Name returns the rule name
func (r *AzurermLinuxFunctionAppSlotMinimumTLSVersion) Name() string {
	return "azurerm_linux_function_app_slot_minimum_tls_version"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermLinuxFunctionAppSlotMinimumTLSVersion) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermLinuxFunctionAppSlotMinimumTLSVersion) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermLinuxFunctionAppSlotMinimumTLSVersion) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check verifies that minimum_tls_version is set to "1.2" or "1.3"
func (r *AzurermLinuxFunctionAppSlotMinimumTLSVersion) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "site_config",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "minimum_tls_version"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	supportedVersions := strings.Join(r.versions, " or ")

	for _, resource := range resources.Blocks {
		siteConfigBlocks := resource.Body.Blocks.OfType("site_config")
		if len(siteConfigBlocks) == 0 {
			runner.EmitIssue(
				r,
				fmt.Sprintf("site_config block is missing, minimum_tls_version should be set to %s", supportedVersions),
				resource.DefRange,
			)
			continue
		}

		siteConfig := siteConfigBlocks[0]
		attribute, exists := siteConfig.Body.Attributes["minimum_tls_version"]
		if !exists {
			runner.EmitIssue(
				r,
				fmt.Sprintf("minimum_tls_version is missing in site_config, should be set to %s", supportedVersions),
				siteConfig.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			if !slices.Contains(r.versions, val) {
				runner.EmitIssue(
					r,
					fmt.Sprintf("minimum_tls_version is set to %s, should be %s", val, supportedVersions),
					attribute.Expr.Range(),
				)
			}
			return nil
		}, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

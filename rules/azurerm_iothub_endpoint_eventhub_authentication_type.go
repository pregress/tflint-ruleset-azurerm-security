package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermIoTHubEndpointEventHubAuthenticationType checks that the authentication_type for azurerm_iothub_endpoint_eventhub is "identityBased"
type AzurermIoTHubEndpointEventHubAuthenticationType struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermIoTHubEndpointEventHubAuthenticationType returns a new rule instance
func NewAzurermIoTHubEndpointEventHubAuthenticationType() *AzurermIoTHubEndpointEventHubAuthenticationType {
	return &AzurermIoTHubEndpointEventHubAuthenticationType{
		resourceType:  "azurerm_iothub_endpoint_eventhub",
		attributeName: "authentication_type",
	}
}

// Name returns the rule name
func (r *AzurermIoTHubEndpointEventHubAuthenticationType) Name() string {
	return "azurerm_iothub_endpoint_eventhub_authentication_type"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermIoTHubEndpointEventHubAuthenticationType) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermIoTHubEndpointEventHubAuthenticationType) Severity() tflint.Severity {
	return tflint.NOTICE
}

// Link returns the rule reference link
func (r *AzurermIoTHubEndpointEventHubAuthenticationType) Link() string {	
	return project.ReferenceLink(r.Name())
}

// Check checks if the authentication_type for azurerm_iothub_endpoint_eventhub is "identityBased"
func (r *AzurermIoTHubEndpointEventHubAuthenticationType) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: r.attributeName},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		attribute, exists := resource.Body.Attributes[r.attributeName]
		if !exists {
			// Emit an issue if the attribute does not exist
			runner.EmitIssue(
				r,
				"authentication_type is not defined and should be \"identityBased\"",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			if val != "identityBased" {
				runner.EmitIssue(
					r,
					"authentication_type should be \"identityBased\"",
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

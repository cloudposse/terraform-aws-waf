package test

import (
	"flag"
	"math/rand"
	"strconv"
	"testing"
	"time"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

var (
	words     = flag.Int("words", 2, "The number of words in the pet name")
	separator = flag.String("separator", "-", "The separator between words in the pet name")
)

// Test the Terraform module in examples/complete using Terratest.
func TestExamplesComplete(t *testing.T) {
	t.Parallel()

	rand.Seed(time.Now().UnixNano())
	randID := strconv.Itoa(rand.Intn(100000))
	attributes := []string{randID}
	var waf_name = petname.Generate(*words, *separator)
	terraformOptions := &terraform.Options{
		// The path to where our Terraform code is located
		TerraformDir: "../../examples/complete",
		Upgrade:      true,
		// Variables to pass to our Terraform code using -var-file options
		VarFiles: []string{"fixtures.us-east-2.tfvars"},
		// We always include a random attribute so that parallel tests
		// and AWS resources do not interfere with each other
		Vars: map[string]interface{}{
			"attributes": attributes,
			"waf_name":   waf_name,
		},
	}
	// At the end of the test, run `terraform destroy` to clean up any resources that were created
	defer terraform.Destroy(t, terraformOptions)

	// This will run `terraform init` and `terraform apply` and fail the test if there are any errors
	terraform.InitAndApply(t, terraformOptions)

	// Run `terraform output` to get the value of an output variable
	id := terraform.Output(t, terraformOptions, "id")
	arn := terraform.Output(t, terraformOptions, "arn")
	capacity := terraform.Output(t, terraformOptions, "capacity")

	assert.NotEmpty(t, id)
	assert.Contains(t, arn, "arn:aws:wafv2:")
	assert.NotEmpty(t, capacity)
}

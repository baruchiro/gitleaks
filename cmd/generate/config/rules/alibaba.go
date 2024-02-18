package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// downladed accessPair as CSV from alibaba
var accessPair = "AccessKey ID,AccessKey Secret\nLTAI" + secrets.NewSecret(hex("20")) + "," + secrets.NewSecret(alphaNumeric("30"))

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
		RuleID:      "alibaba-access-key-id",
		Regex:       generateUniqueTokenRegex(`(LTAI)(?i)[a-z0-9]{20}`, true),
		Keywords:    []string{"LTAI", "AccessKey", "AccessKey", "Secret"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + secrets.NewSecret(hex("20")) + "\"",
		accessPair, // failed because the prefix is \n and suffix is ,
	}
	return validate(r, tps, nil)
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		RuleID:      "alibaba-secret-key",
		Regex: generateSemiGenericRegex([]string{"alibaba"},
			alphaNumeric("30"), true),

		Keywords: []string{"alibaba"},
	}

	// validate
	tps := []string{
		generateSampleSecret("alibaba", secrets.NewSecret(alphaNumeric("30"))),
		accessPair,
	}
	return validate(r, tps, nil)
}

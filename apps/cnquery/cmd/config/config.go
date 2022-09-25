package config

import (
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go.mondoo.com/cnquery"
	"go.mondoo.com/cnquery/upstream"
)

const defaultAPIendpoint = "https://us.api.mondoo.com"

func ReadConfig() (*CliConfig, error) {
	// load viper config into a struct
	var opts CliConfig
	err := viper.Unmarshal(&opts)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode into config struct")
	}

	return &opts, nil
}

type CliConfig struct {
	// client identifier
	AgentMrn string `json:"agent_mrn,omitempty" mapstructure:"agent_mrn"`

	// service account credentials
	ServiceAccountMrn string `json:"mrn,omitempty" mapstructure:"mrn"`
	ParentMrn         string `json:"space_mrn,omitempty" mapstructure:"parent_mrn"`
	SpaceMrn          string `json:"space_mrn,omitempty" mapstructure:"space_mrn"`
	PrivateKey        string `json:"private_key,omitempty" mapstructure:"private_key"`
	Certificate       string `json:"certificate,omitempty" mapstructure:"certificate"`
	APIEndpoint       string `json:"api_endpoint,omitempty" mapstructure:"api_endpoint"`

	// authentication
	AuthenticationMechanism string `json:"auth_mechanism,omitempty" mapstructure:"auth_mechanism"`

	// client features
	Features []string `json:"features,omitempty" mapstructure:"features"`

	// labels that will be applied to all assets
	Labels map[string]string `json:"labels,omitempty" mapstructure:"labels"`
}

func (c *CliConfig) GetFeatures() cnquery.Features {
	bitSet := make([]bool, 256)
	flags := []byte{}

	for _, f := range cnquery.DefaultFeatures {
		if !bitSet[f] {
			bitSet[f] = true
			flags = append(flags, f)
		}
	}

	for _, name := range c.Features {
		flag, ok := cnquery.FeaturesValue[name]
		if ok {
			if !bitSet[byte(flag)] {
				bitSet[byte(flag)] = true
				flags = append(flags, byte(flag))
			}
		} else {
			log.Warn().Str("feature", name).Msg("could not parse feature")
		}
	}

	return flags
}

func (c *CliConfig) GetServiceCredential() *upstream.ServiceAccountCredentials {
	if c.AuthenticationMechanism == "ssh" {
		log.Info().Msg("using ssh authentication, generate temporary credentials")
		serviceAccount, err := upstream.ExchangeSSHKey(c.UpstreamApiEndpoint(), c.ServiceAccountMrn, c.GetParentMrn())
		if err != nil {
			log.Error().Err(err).Msg("could not exchange ssh key")
			return nil
		}

		// data, _ := yaml.Marshal(serviceAccount)
		// fmt.Println(string(data))
		log.Info().Msg("successfully exchanged ssh key with service account")

		return serviceAccount
	}

	return &upstream.ServiceAccountCredentials{
		Mrn:         c.ServiceAccountMrn,
		ParentMrn:   c.GetParentMrn(),
		PrivateKey:  c.PrivateKey,
		Certificate: c.Certificate,
		ApiEndpoint: c.APIEndpoint,
	}
}

func (c *CliConfig) GetParentMrn() string {
	parent := c.ParentMrn

	// fallback to old space_mrn config
	if parent == "" {
		parent = c.SpaceMrn
	}

	return parent
}

func (c *CliConfig) UpstreamApiEndpoint() string {
	apiEndpoint := c.APIEndpoint

	// fallback to default api if nothing was set
	if apiEndpoint == "" {
		apiEndpoint = defaultAPIendpoint
	}

	return apiEndpoint
}

package resolver

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/cnquery/motor"
	"go.mondoo.com/cnquery/motor/providers"
	"go.mondoo.com/cnquery/motor/providers/arista"
	aws_provider "go.mondoo.com/cnquery/motor/providers/aws"
	"go.mondoo.com/cnquery/motor/providers/awsec2ebs"
	"go.mondoo.com/cnquery/motor/providers/azure"
	"go.mondoo.com/cnquery/motor/providers/container"
	"go.mondoo.com/cnquery/motor/providers/equinix"
	"go.mondoo.com/cnquery/motor/providers/fs"
	"go.mondoo.com/cnquery/motor/providers/gcp"
	"go.mondoo.com/cnquery/motor/providers/github"
	"go.mondoo.com/cnquery/motor/providers/gitlab"
	"go.mondoo.com/cnquery/motor/providers/ipmi"
	k8s_provider "go.mondoo.com/cnquery/motor/providers/k8s"
	"go.mondoo.com/cnquery/motor/providers/local"
	"go.mondoo.com/cnquery/motor/providers/mock"
	"go.mondoo.com/cnquery/motor/providers/ms365"
	"go.mondoo.com/cnquery/motor/providers/network"
	"go.mondoo.com/cnquery/motor/providers/ssh"
	"go.mondoo.com/cnquery/motor/providers/tar"
	"go.mondoo.com/cnquery/motor/providers/terraform"
	"go.mondoo.com/cnquery/motor/providers/vmwareguestapi"
	"go.mondoo.com/cnquery/motor/providers/vsphere"
	"go.mondoo.com/cnquery/motor/providers/winrm"
	"go.mondoo.com/cnquery/motor/vault"
	"google.golang.org/protobuf/proto"
)

var providerDevelopmentStatus = map[providers.ProviderType]string{
	providers.ProviderType_AWS_EC2_EBS: "experimental",
}

func warnIncompleteFeature(backend providers.ProviderType) {
	if providerDevelopmentStatus[backend] != "" {
		log.Warn().Str("feature", backend.String()).Str("status", providerDevelopmentStatus[backend]).Msg("WARNING: you are using an early access feature")
	}
}

// NewMotorConnection establishes a motor connection by using the provided provider configuration
// By default, it uses the id detector mechanisms provided by the provider. User can overwrite that
// behaviour by optionally passing id detector identifier
func NewMotorConnection(ctx context.Context, tc *providers.Config, credentialFn func(cred *vault.Credential) (*vault.Credential, error)) (*motor.Motor, error) {
	log.Debug().Msg("establish motor connection")
	var m *motor.Motor

	warnIncompleteFeature(tc.Backend)

	// we clone the config here, and replace all credential references with the real references
	// the clone is important so that credentials are not leaked outside of the function
	resolvedConfig := proto.Clone(tc).(*providers.Config)
	resolvedCredentials := []*vault.Credential{}
	for i := range resolvedConfig.Credentials {
		credential := resolvedConfig.Credentials[i]
		if credential.SecretId != "" && credentialFn != nil {
			resolvedCredential, err := credentialFn(credential)
			if err != nil {
				log.Debug().Str("secret-id", credential.SecretId).Err(err).Msg("could not fetch secret for motor connection")
				return nil, err
			}
			credential = resolvedCredential
		}
		resolvedCredentials = append(resolvedCredentials, credential)
	}
	resolvedConfig.Credentials = resolvedCredentials

	// establish connection
	switch resolvedConfig.Backend {
	case providers.ProviderType_MOCK:
		log.Debug().Msg("connection> load mock provider")
		p, err := mock.NewFromToml(resolvedConfig)
		if err != nil {
			return nil, err
		}

		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_LOCAL_OS:
		log.Debug().Msg("connection> load local provider")
		p, err := local.NewWithConfig(resolvedConfig)
		if err != nil {
			return nil, err
		}

		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_TAR:
		log.Debug().Msg("connection> load tar provider")
		p, err := tar.New(resolvedConfig)
		if err != nil {
			return nil, err
		}

		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_CONTAINER_REGISTRY:
		log.Debug().Msg("connection> load container registry provider")
		p, err := container.NewContainerRegistryImage(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_DOCKER_ENGINE_CONTAINER:
		log.Debug().Msg("connection> load docker engine container provider")
		p, err := container.NewDockerEngineContainer(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_DOCKER_ENGINE_IMAGE:
		log.Debug().Msg("connection> load docker engine image provider")
		p, err := container.NewDockerEngineImage(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_SSH:
		log.Debug().Msg("connection> load ssh provider")
		p, err := ssh.New(resolvedConfig)
		if err != nil {
			return nil, err
		}

		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_WINRM:
		log.Debug().Msg("connection> load winrm provider")
		p, err := winrm.New(resolvedConfig)
		if err != nil {
			return nil, err
		}

		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_VSPHERE:
		log.Debug().Msg("connection> load vsphere provider")
		p, err := vsphere.New(resolvedConfig)
		if err != nil {
			return nil, err
		}

		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_ARISTAEOS:
		log.Debug().Msg("connection> load arista eos provider")
		p, err := arista.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_AWS:
		log.Debug().Msg("connection> load aws provider")
		p, err := aws_provider.New(resolvedConfig, aws_provider.TransportOptions(resolvedConfig.Options)...)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_GCP:
		log.Debug().Msg("connection> load gcp provider")
		p, err := gcp.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_AZURE:
		log.Debug().Msg("connection> load azure provider")
		p, err := azure.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_MS365:
		log.Debug().Msg("connection> load microsoft 365 provider")
		p, err := ms365.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_IPMI:
		log.Debug().Msg("connection> load ipmi provider")
		p, err := ipmi.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_VSPHERE_VM:
		p, err := vmwareguestapi.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_FS:
		p, err := fs.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p, motor.WithRecoding(resolvedConfig.Record))
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_EQUINIX_METAL:
		p, err := equinix.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_K8S:
		p, err := k8s_provider.New(ctx, resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_GITHUB:
		p, err := github.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_GITLAB:
		p, err := gitlab.New(resolvedConfig)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_AWS_EC2_EBS:
		p, err := awsec2ebs.New(tc)
		if err != nil {
			return nil, err
		}
		// TODO (jaym) before merge: The ebs provider is being lost. This
		// is problematic. It will break the platform id detection being added
		m, err = motor.New(p.FsProvider)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_TERRAFORM:
		p, err := terraform.New(tc)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	case providers.ProviderType_HOST:
		p, err := network.New(tc)
		if err != nil {
			return nil, err
		}
		m, err = motor.New(p)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("connection> unsupported backend '%s'", resolvedConfig.Backend)
	}

	return m, nil
}

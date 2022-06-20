package k8s

import (
	"errors"

	"github.com/spf13/afero"
	platform "go.mondoo.io/mondoo/motor/platform"
	"go.mondoo.io/mondoo/motor/transports"
	"go.mondoo.io/mondoo/motor/transports/fsutil"
	"go.mondoo.io/mondoo/motor/transports/k8s/resources"
	"k8s.io/apimachinery/pkg/version"
)

type Transport interface {
	transports.Transport
	transports.TransportPlatformIdentifier
	Name() (string, error)
	PlatformInfo() *platform.Platform
	Connector() Connector
	Resources(kind string, name string) (*ResourceResult, error)
	ServerVersion() *version.Info
	SupportedResourceTypes() (*resources.ApiResourceIndex, error)
}

const (
	OPTION_MANIFEST  = "path"
	OPTION_NAMESPACE = "namespace"
)

// New initializes the k8s transport and loads a configuration.
// Supported options are:
// - namespace: limits the resources to a specific namespace
// - path: use a manifest file instead of live API
func New(tc *transports.TransportConfig) (Transport, error) {
	var connector Connector

	if tc.Backend != transports.TransportBackend_CONNECTION_K8S {
		return nil, errors.New("backend is not supported for k8s transport")
	}

	manifestFile, manifestDefined := tc.Options[OPTION_MANIFEST]
	if manifestDefined {
		connector = NewManifestConnector(WithManifestFile(manifestFile), WithNamespace(tc.Options[OPTION_NAMESPACE]))
	} else {
		var err error
		connector, err = NewApiConnector(tc.Options[OPTION_NAMESPACE])
		if err != nil {
			return nil, err
		}
	}

	return &transport{
		connector: connector,
		opts:      tc.Options,
	}, nil
}

type transport struct {
	opts      map[string]string
	connector Connector
}

func (t *transport) Connector() Connector {
	return t.connector
}

func (t *transport) RunCommand(command string) (*transports.Command, error) {
	return nil, errors.New("k8s does not implement RunCommand")
}

func (t *transport) FileInfo(path string) (transports.FileInfoDetails, error) {
	return transports.FileInfoDetails{}, errors.New("k8s does not implement FileInfo")
}

func (t *transport) FS() afero.Fs {
	return &fsutil.NoFs{}
}

func (t *transport) Close() {}

func (t *transport) Capabilities() transports.Capabilities {
	return transports.Capabilities{}
}

func (t *transport) Options() map[string]string {
	return t.opts
}

func (t *transport) Kind() transports.Kind {
	return transports.Kind_KIND_API
}

func (t *transport) Runtime() string {
	return transports.RUNTIME_KUBERNETES
}

func (t *transport) PlatformIdDetectors() []transports.PlatformIdDetector {
	return []transports.PlatformIdDetector{
		transports.TransportPlatformIdentifierDetector,
	}
}

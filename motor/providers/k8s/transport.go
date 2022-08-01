package k8s

//go:generate  go run github.com/golang/mock/mockgen -source=./transport.go -destination=./mock_transport.go -package=k8s

import (
	"errors"
	"strings"

	platform "go.mondoo.io/mondoo/motor/platform"
	"go.mondoo.io/mondoo/motor/providers"
	"go.mondoo.io/mondoo/motor/providers/k8s/resources"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
)

const (
	OPTION_MANIFEST  = "path"
	OPTION_NAMESPACE = "namespace"
)

type Transport interface {
	providers.Transport
	providers.TransportPlatformIdentifier
	Name() (string, error)
	PlatformInfo() *platform.Platform

	// Resources returns the resources that match the provided kind and name. If not kind and name
	// are provided, then all cluster resources are returned.
	Resources(kind string, name string, namespace string) (*ResourceResult, error)
	ServerVersion() *version.Info
	SupportedResourceTypes() (*resources.ApiResourceIndex, error)

	// ID of the Cluster or Manifest file
	ID() (string, error)
	// MRN style platform identifier
	PlatformIdentifier() (string, error)
	Namespaces() ([]v1.Namespace, error)
	Pod(namespace string, name string) (*v1.Pod, error)
	Pods(namespace v1.Namespace) ([]v1.Pod, error)
	CronJob(namespace string, name string) (*batchv1.CronJob, error)
	CronJobs(namespace v1.Namespace) ([]batchv1.CronJob, error)
}

type ClusterInfo struct {
	Name string
}

type ResourceResult struct {
	Name         string
	Kind         string
	ResourceType *resources.ApiResource // resource type that matched kind

	// Resources the resources that match the name, kind and namespace
	Resources []runtime.Object
	Namespace string
	AllNs     bool
}

// New initializes the k8s transport and loads a configuration.
// Supported options are:
// - namespace: limits the resources to a specific namespace
// - path: use a manifest file instead of live API
func New(tc *providers.TransportConfig) (Transport, error) {
	if tc.Backend != providers.TransportBackend_CONNECTION_K8S {
		return nil, errors.New("backend is not supported for k8s transport")
	}

	manifestFile, manifestDefined := tc.Options[OPTION_MANIFEST]
	if manifestDefined {
		return newManifestTransport(tc.PlatformId, WithManifestFile(manifestFile), WithNamespace(tc.Options[OPTION_NAMESPACE])), nil
	}

	return newApiTransport(tc.Options[OPTION_NAMESPACE], tc.PlatformId)
}

func getPlatformInfo(selectedResourceID string, runtime string) *platform.Platform {
	platformData := &platform.Platform{
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    providers.Kind_KIND_K8S_OBJECT,
		Runtime: runtime,
	}
	switch selected := selectedResourceID; {
	case strings.Contains(selected, "/pods/"):
		platformData.Name = "k8s-pod"
		platformData.Title = "Kubernetes Pod"
		return platformData
	case strings.Contains(selected, "/cronjobs/"):
		platformData.Name = "k8s-cronjob"
		platformData.Title = "Kubernetes CronJob"
		return platformData
	}

	return nil
}

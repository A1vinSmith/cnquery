package k8s

//go:generate  go run github.com/golang/mock/mockgen -source=./provider.go -destination=./mock_provider.go -package=k8s

import (
	"context"
	"fmt"
	"strings"

	platform "go.mondoo.io/mondoo/motor/platform"
	"go.mondoo.io/mondoo/motor/providers"
	"go.mondoo.io/mondoo/motor/providers/k8s/resources"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
)

const (
	OPTION_MANIFEST  = "path"
	OPTION_NAMESPACE = "namespace"
)

var (
	_ providers.Instance = (*apiProvider)(nil)
	_ providers.Instance = (*manifestProvider)(nil)
)

type KubernetesProvider interface {
	providers.Instance
	providers.PlatformIdentifier
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
	Pod(namespace, name string) (*v1.Pod, error)
	Pods(namespace v1.Namespace) ([]v1.Pod, error)
	CronJob(namespace, name string) (*batchv1.CronJob, error)
	CronJobs(namespace v1.Namespace) ([]batchv1.CronJob, error)
	StatefulSet(namespace, name string) (*appsv1.StatefulSet, error)
	StatefulSets(namespace v1.Namespace) ([]appsv1.StatefulSet, error)
	Deployment(namespace, name string) (*appsv1.Deployment, error)
	Deployments(namespace v1.Namespace) ([]appsv1.Deployment, error)
	Job(namespace, name string) (*batchv1.Job, error)
	Jobs(namespace v1.Namespace) ([]batchv1.Job, error)
	ReplicaSet(namespace, name string) (*appsv1.ReplicaSet, error)
	ReplicaSets(namespace v1.Namespace) ([]appsv1.ReplicaSet, error)
	DaemonSet(namespace, name string) (*appsv1.DaemonSet, error)
	DaemonSets(namespace v1.Namespace) ([]appsv1.DaemonSet, error)
	Secret(namespace, name string) (*v1.Secret, error)
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

// New initializes the k8s provider and loads a configuration.
// Supported options are:
// - namespace: limits the resources to a specific namespace
// - path: use a manifest file instead of live API
func New(ctx context.Context, tc *providers.Config) (KubernetesProvider, error) {
	if tc.Backend != providers.ProviderType_K8S {
		return nil, providers.ErrProviderTypeDoesNotMatch
	}

	manifestFile, manifestDefined := tc.Options[OPTION_MANIFEST]
	if manifestDefined {
		return newManifestProvider(tc.PlatformId, WithManifestFile(manifestFile), WithNamespace(tc.Options[OPTION_NAMESPACE])), nil
	}

	// initialize resource cache, so that the same k8s resources can be re-used
	dCache, ok := resources.GetDiscoveryCache(ctx)
	if !ok {
		return nil, fmt.Errorf("context does not have an initialized discovery cache")
	}

	return newApiProvider(tc.Options[OPTION_NAMESPACE], tc.PlatformId, dCache)
}

func getPlatformInfo(selectedResourceID string, runtime string) *platform.Platform {
	// We need this at two places (discovery and tranport)
	// Here it is needed for the transport and this is what is shown on the cli
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
	case strings.Contains(selected, "/statefulsets/"):
		platformData.Name = "k8s-statefulset"
		platformData.Title = "Kubernetes StatefulSet"
		return platformData
	case strings.Contains(selected, "/deployments/"):
		platformData.Name = "k8s-deployment"
		platformData.Title = "Kubernetes Deployment"
		return platformData
	case strings.Contains(selected, "/jobs/"):
		platformData.Name = "k8s-job"
		platformData.Title = "Kubernetes Job"
		return platformData
	case strings.Contains(selected, "/replicasets/"):
		platformData.Name = "k8s-replicaset"
		platformData.Title = "Kubernetes ReplicaSet"
		return platformData
	case strings.Contains(selected, "/daemonsets/"):
		platformData.Name = "k8s-daemonset"
		platformData.Title = "Kubernetes DaemonSet"
		return platformData
	}

	return nil
}

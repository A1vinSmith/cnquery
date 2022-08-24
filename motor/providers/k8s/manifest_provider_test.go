package k8s

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/cnquery/motor/providers/k8s/resources"
)

func TestManifestDeployment(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.deployment.yaml"
	transport := newManifestProvider("", WithManifestFile(manifestFile))
	require.NotNil(t, transport)
	res, err := transport.Resources("deployment", "centos", "default")
	require.NoError(t, err)
	assert.Equal(t, "centos", res.Name)
	assert.Equal(t, "deployment", res.Kind)
	assert.Equal(t, "k8s-manifest", transport.PlatformInfo().Runtime)
	assert.Equal(t, 1, len(res.Resources))
}

func TestManifestCronJob(t *testing.T) {
	manifestFile := "./resources/testdata/batchv1.cronjob.yaml"
	transport := newManifestProvider("", WithManifestFile(manifestFile))
	require.NotNil(t, transport)
	res, err := transport.Resources("cronjob", "mondoo-client-k8s-scan", "mondoo-operator")
	require.NoError(t, err)
	assert.Equal(t, "mondoo-client-k8s-scan", res.Name)
	assert.Equal(t, "cronjob", res.Kind)
	assert.Equal(t, "k8s-manifest", transport.PlatformInfo().Runtime)
	assert.Equal(t, 1, len(res.Resources))
}

func TestManifestInmemory(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.deployment.yaml"
	data, err := os.ReadFile(manifestFile)
	require.NoError(t, err)

	objects, err := resources.ResourcesFromManifest(bytes.NewReader(data))
	require.NoError(t, err)

	transport := newManifestProvider("", WithRuntimeObjects(objects))
	require.NotNil(t, transport)
	res, err := transport.Resources("deployment", "centos", "default")
	require.NoError(t, err)
	assert.Equal(t, "centos", res.Name)
	assert.Equal(t, "deployment", res.Kind)
	assert.Equal(t, "k8s-manifest", transport.PlatformInfo().Runtime)
	assert.Equal(t, 1, len(res.Resources))
}

func TestManifestPod(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.pod.yaml"
	transport := newManifestProvider("", WithManifestFile(manifestFile))
	require.NotNil(t, transport)

	namespaces, err := transport.Namespaces()
	require.NoError(t, err)
	assert.Equal(t, 1, len(namespaces))

	pods, err := transport.Pods(namespaces[0])
	require.NoError(t, err)
	assert.Equal(t, "k8s-manifest", transport.PlatformInfo().Runtime)
	assert.Equal(t, 2, len(pods))
}

func TestManifestStatefulSet(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.statefulset.yaml"
	transport := newManifestProvider("", WithManifestFile(manifestFile))
	require.NotNil(t, transport)
	res, err := transport.Resources("statefulset", "mondoo-statefulset", "default")
	require.NoError(t, err)
	assert.Equal(t, "mondoo-statefulset", res.Name)
	assert.Equal(t, "statefulset", res.Kind)
	assert.Equal(t, "k8s-manifest", transport.PlatformInfo().Runtime)
	assert.Equal(t, 1, len(res.Resources))
}

func TestManifestJob(t *testing.T) {
	manifestFile := "./resources/testdata/batchv1.job.yaml"
	transport := newManifestProvider("", WithManifestFile(manifestFile))
	require.NotNil(t, transport)
	res, err := transport.Resources("job", "mondoo-client-k8s-scan", "mondoo-operator")
	require.NoError(t, err)
	assert.Equal(t, "mondoo-client-k8s-scan", res.Name)
	assert.Equal(t, "job", res.Kind)
	assert.Equal(t, "k8s-manifest", transport.PlatformInfo().Runtime)
	assert.Equal(t, 1, len(res.Resources))
}

func TestManifestReplicaSet(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.replicaset.yaml"
	transport := newManifestProvider("", WithManifestFile(manifestFile))
	require.NotNil(t, transport)

	namespaces, err := transport.Namespaces()
	require.NoError(t, err)
	assert.Equal(t, 1, len(namespaces))

	pods, err := transport.ReplicaSets(namespaces[0])
	require.NoError(t, err)
	assert.Equal(t, 1, len(pods))
}

func TestManifestDaemonSet(t *testing.T) {
	manifestFile := "./resources/testdata/appsv1.daemonset.yaml"
	transport := newManifestProvider("", WithManifestFile(manifestFile))
	require.NotNil(t, transport)
	res, err := transport.Resources("daemonset", "mondoo-daemonset", "default")
	require.NoError(t, err)
	assert.Equal(t, "mondoo-daemonset", res.Name)
	assert.Equal(t, "daemonset", res.Kind)
	assert.Equal(t, "k8s-manifest", transport.PlatformInfo().Runtime)
	assert.Equal(t, 1, len(res.Resources))
}

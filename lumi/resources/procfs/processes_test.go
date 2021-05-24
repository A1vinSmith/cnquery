package procfs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.io/mondoo/motor/transports"
	"go.mondoo.io/mondoo/motor/transports/mock"
)

func TestParseProcessStatus(t *testing.T) {
	path := "./testdata/process-pid1.toml"
	trans, err := mock.NewFromToml(&transports.TransportConfig{Backend: transports.TransportBackend_CONNECTION_MOCK, Path: path})
	require.NoError(t, err)

	f, err := trans.FS().Open("/proc/1/status")
	require.NoError(t, err)
	defer f.Close()

	processStatus, err := ParseProcessStatus(f)
	require.NoError(t, err)

	assert.NotNil(t, processStatus, "process is not nil")
	assert.Equal(t, "bash", processStatus.Executable, "detected process name")
}

func TestParseProcessCmdline(t *testing.T) {
	path := "./testdata/process-pid1.toml"
	trans, err := mock.NewFromToml(&transports.TransportConfig{Backend: transports.TransportBackend_CONNECTION_MOCK, Path: path})
	require.NoError(t, err)

	f, err := trans.FS().Open("/proc/1/cmdline")
	require.NoError(t, err)
	defer f.Close()

	cmd, err := ParseProcessCmdline(f)
	require.NoError(t, err)
	assert.Equal(t, "/bin/bash", cmd, "detected process name")
}

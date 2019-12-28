package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	mock "go.mondoo.io/mondoo/motor/motoros/mock/toml"
	"go.mondoo.io/mondoo/motor/motoros/types"
)

func TestMacOsXPackageParser(t *testing.T) {
	mock, err := mock.New(&types.Endpoint{Backend: "mock", Path: "./testdata/packages_macos.toml"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("system_profiler SPApplicationsDataType -xml")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseMacOSPackages(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(m), "detected the right amount of packages")

	assert.Equal(t, "Preview", m[0].Name, "pkg name detected")
	assert.Equal(t, "10.0", m[0].Version, "pkg version detected")

	assert.Equal(t, "Contacts", m[1].Name, "pkg name detected")
	assert.Equal(t, "11.0", m[1].Version, "pkg version detected")
}

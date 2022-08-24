//go:build linux || darwin || netbsd || openbsd || freebsd
// +build linux darwin netbsd openbsd freebsd

package windows

import (
	"go.mondoo.com/cnquery/motor/providers/os"
)

func GetWmiInformation(p os.OperatingSystemProvider) (*WmicOSInformation, error) {
	return powershellGetWmiInformation(p)
}

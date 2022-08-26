//go:build windows
// +build windows

package client

type registry string

const (
	PATH     registry = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TPM"
	D_WORD   registry = "PlatformLogRetention"
	location          = "\\logs\\measuredboot"
	sys               = "SYSTEMROOT"
)

func getRealEventLog() ([]byte, error) {
	var path = os.GetEnv(sys) + location
	return ioutil.ReadFile(path)
}

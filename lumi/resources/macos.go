package resources

import (
	"bytes"
	"errors"
	"io/ioutil"
	"strings"

	"go.mondoo.io/mondoo/lumi/resources/macos"
	"go.mondoo.io/mondoo/lumi/resources/plist"
)

func (m *lumiMacos) id() (string, error) {
	return "macos", nil
}

func (m *lumiMacos) GetUserPreferences() (map[string]interface{}, error) {
	res := map[string]interface{}{}
	preferences, err := macos.NewPreferences(m.Runtime.Motor.Transport).UserPreferences()
	if err != nil {
		return nil, err
	}

	for k := range preferences {
		res[k] = preferences[k]
	}
	return res, nil
}

func (m *lumiMacos) GetUserHostPreferences() (map[string]interface{}, error) {
	res := map[string]interface{}{}
	preferences, err := macos.NewPreferences(m.Runtime.Motor.Transport).UserHostPreferences()
	if err != nil {
		return nil, err
	}

	for k := range preferences {
		res[k] = preferences[k]
	}
	return res, nil
}

func (m *lumiMacos) GetGlobalAccountPolicies() (map[string]interface{}, error) {
	cmd, err := m.Runtime.Motor.Transport.RunCommand("pwpolicy -getaccountpolicies")
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	return plist.Decode(bytes.NewReader(data))
}

func (m *lumiMacosSystemsetup) id() (string, error) {
	return "macos.systemsetup", nil
}

func (m *lumiMacosSystemsetup) runCmd(command string) (string, error) {
	cmd, err := m.Runtime.Motor.Transport.RunCommand(command)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	// NOTE: systemsetup returns exit 0 even if it does not have enough permissions
	// Therefore we need to handle this case here
	if strings.TrimSpace(string(data)) == "You need administrator access to run this tool... exiting!" {
		return "", errors.New("macos.systemsetup needs elevated permissions")
	}

	return string(data), nil
}

func (m *lumiMacosSystemsetup) GetDate() (string, error) {
	data, err := m.runCmd("systemsetup -getdate")
	return macos.SystemSetupCmdOutput{}.ParseDate(data), err
}

func (m *lumiMacosSystemsetup) GetTime() (string, error) {
	data, err := m.runCmd("systemsetup -gettime")
	return macos.SystemSetupCmdOutput{}.ParseTime(data), err
}

func (m *lumiMacosSystemsetup) GetTimeZone() (string, error) {
	data, err := m.runCmd("systemsetup -gettimezone")
	return macos.SystemSetupCmdOutput{}.ParseTimeZone(data), err
}

func (m *lumiMacosSystemsetup) GetUsingNetworkTime() (string, error) {
	data, err := m.runCmd("systemsetup -getusingnetworktime")
	return macos.SystemSetupCmdOutput{}.ParseUsingNetworktTime(data), err
}

func (m *lumiMacosSystemsetup) GetNetworkTimeServer() (string, error) {
	data, err := m.runCmd("systemsetup -getnetworktimeserver")
	return macos.SystemSetupCmdOutput{}.ParseNetworkTimeServer(data), err
}

func (m *lumiMacosSystemsetup) GetSleep() ([]interface{}, error) {
	data, err := m.runCmd("systemsetup -getsleep")
	return strSliceToInterface(macos.SystemSetupCmdOutput{}.ParseSleep(data)), err
}

func (m *lumiMacosSystemsetup) GetDisplaySleep() (string, error) {
	data, err := m.runCmd("systemsetup -getdisplaysleep")
	return macos.SystemSetupCmdOutput{}.ParseDisplaySleep(data), err
}

func (m *lumiMacosSystemsetup) GetHarddiskSleep() (string, error) {
	data, err := m.runCmd("systemsetup -getdisplaysleep")
	return macos.SystemSetupCmdOutput{}.ParseHardDiskSleep(data), err
}

func (m *lumiMacosSystemsetup) GetWakeOnModem() (string, error) {
	data, err := m.runCmd("systemsetup -getwakeonmodem")
	return macos.SystemSetupCmdOutput{}.ParseWakeOnModem(data), err
}

func (m *lumiMacosSystemsetup) GetWakeOnNetworkAccess() (string, error) {
	data, err := m.runCmd("systemsetup -getwakeonnetworkaccess")
	return macos.SystemSetupCmdOutput{}.ParseWakeOnNetwork(data), err
}

func (m *lumiMacosSystemsetup) GetRestartPowerFailure() (string, error) {
	data, err := m.runCmd("systemsetup -getrestartpowerfailure")
	return macos.SystemSetupCmdOutput{}.ParseRestartPowerFailure(data), err
}

func (m *lumiMacosSystemsetup) GetRestartFreeze() (string, error) {
	data, err := m.runCmd("systemsetup -getrestartfreeze")
	return macos.SystemSetupCmdOutput{}.ParseRestartFreeze(data), err
}

func (m *lumiMacosSystemsetup) GetAllowPowerButtonToSleepComputer() (string, error) {
	data, err := m.runCmd("systemsetup -getallowpowerbuttontosleepcomputer")
	return macos.SystemSetupCmdOutput{}.ParseAllowPowerButtonToSleep(data), err
}

func (m *lumiMacosSystemsetup) GetRemoteLogin() (string, error) {
	data, err := m.runCmd("systemsetup -getremotelogin")
	return macos.SystemSetupCmdOutput{}.ParseRemoteLogin(data), err
}

func (m *lumiMacosSystemsetup) GetRemoteAppleEvents() (string, error) {
	data, err := m.runCmd("systemsetup -getremoteappleevents")
	return macos.SystemSetupCmdOutput{}.ParseRemoteAppleEvents(data), err
}

func (m *lumiMacosSystemsetup) GetComputerName() (string, error) {
	data, err := m.runCmd("systemsetup -getcomputername")
	return macos.SystemSetupCmdOutput{}.ParseComputerName(data), err
}

func (m *lumiMacosSystemsetup) GetLocalSubnetName() (string, error) {
	data, err := m.runCmd("systemsetup -getlocalsubnetname")
	return macos.SystemSetupCmdOutput{}.ParseLocalSubnetname(data), err
}

func (m *lumiMacosSystemsetup) GetStartupDisk() (string, error) {
	data, err := m.runCmd("systemsetup -getstartupdisk")
	return data, err
}

func (m *lumiMacosSystemsetup) GetWaitForStartupAfterPowerFailure() (string, error) {
	data, err := m.runCmd("systemsetup -getwaitforstartupafterpowerfailure")
	return macos.SystemSetupCmdOutput{}.ParseWaitForStartupAfterPowerFailure(data), err
}

func (m *lumiMacosSystemsetup) GetDisableKeyboardWhenEnclosureLockIsEngaged() (string, error) {
	data, err := m.runCmd("systemsetup -getdisablekeyboardwhenenclosurelockisengaged")
	return macos.SystemSetupCmdOutput{}.ParseDisableKeyboardWhenEnclosureLockIsEngaged(data), err
}

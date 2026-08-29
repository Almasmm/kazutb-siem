//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var privateFileSystemSIDs = []string{"S-1-5-18", "S-1-5-32-544"} // SYSTEM, Builtin Administrators

func currentWindowsUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current Windows token user: %w", err)
	}
	return user.User.Sid, nil
}

func securePrivateFile(file *os.File) error {
	current, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	sids := []*windows.SID{current}
	seen := map[string]bool{current.String(): true}
	for _, value := range privateFileSystemSIDs {
		sid, sidErr := windows.StringToSid(value)
		if sidErr != nil {
			return fmt.Errorf("parse private-state trustee %s: %w", value, sidErr)
		}
		if !seen[sid.String()] {
			sids = append(sids, sid)
			seen[sid.String()] = true
		}
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for index, sid := range sids {
		var trusteeType windows.TRUSTEE_TYPE = windows.TRUSTEE_IS_WELL_KNOWN_GROUP
		if index == 0 {
			trusteeType = windows.TRUSTEE_IS_USER
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: trusteeType,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build private-state Windows ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(file.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return fmt.Errorf("protect private-state Windows ACL: %w", err)
	}
	return ValidatePrivateFileSecurity(file.Name())
}

// ValidatePrivateFileSecurity verifies a protected DACL and rejects every
// access-allow ACE except the current identity, SYSTEM and Administrators.
func ValidatePrivateFileSecurity(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read private-state Windows ACL: %w", err)
	}
	if descriptor == nil {
		return errors.New("private-state Windows security descriptor is missing")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read private-state Windows ACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("private-state Windows DACL inherits permissions")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("private-state Windows DACL is missing")
	}
	current, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	allowed := map[string]bool{current.String(): true}
	for _, value := range privateFileSystemSIDs {
		allowed[value] = true
	}
	foundCurrent := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read private-state Windows ACE %d: %w", index, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		value := sid.String()
		if !allowed[value] {
			return fmt.Errorf("private-state Windows ACL grants access to %s", value)
		}
		if value == current.String() {
			foundCurrent = true
		}
	}
	if !foundCurrent {
		return errors.New("private-state Windows ACL does not grant the current identity access")
	}
	return nil
}

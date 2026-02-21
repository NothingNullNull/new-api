package service

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/go-ldap/ldap/v3"
)

// LDAPAuth authenticates a user against LDAP server
// Returns true if authentication is successful, false otherwise
func LDAPAuth(username, password string) (bool, error) {
	if !common.LDAPEnabled {
		return false, errors.New("LDAP authentication is not enabled")
	}

	if username == "" || password == "" {
		return false, errors.New("username or password is empty")
	}

	if common.LDAPServerURL == "" {
		return false, errors.New("LDAP server URL is not configured")
	}

	// Connect to LDAP server
	var l *ldap.Conn
	var err error

	// Check if LDAPS (secure LDAP)
	if strings.HasPrefix(common.LDAPServerURL, "ldaps://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: common.TLSInsecureSkipVerify,
		}
		l, err = ldap.DialURL(common.LDAPServerURL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		l, err = ldap.DialURL(common.LDAPServerURL)
	}

	if err != nil {
		common.SysError(fmt.Sprintf("failed to connect to LDAP server: %v", err))
		return false, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer l.Close()

	// Bind with service account if configured
	if common.LDAPBindDN != "" && common.LDAPBindPassword != "" {
		err = l.Bind(common.LDAPBindDN, common.LDAPBindPassword)
		if err != nil {
			common.SysError(fmt.Sprintf("failed to bind with service account: %v", err))
			return false, fmt.Errorf("failed to bind with service account: %w", err)
		}
	}

	// Search for user DN
	userFilter := strings.ReplaceAll(common.LDAPUserFilter, "%s", ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		common.LDAPBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		userFilter,
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		common.SysError(fmt.Sprintf("LDAP search failed: %v", err))
		return false, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		common.SysLog(fmt.Sprintf("LDAP user not found: %s", username))
		return false, nil
	}

	if len(sr.Entries) > 1 {
		common.SysError(fmt.Sprintf("multiple LDAP users found for: %s", username))
		return false, errors.New("multiple users found")
	}

	userDN := sr.Entries[0].DN

	// Authenticate user
	err = l.Bind(userDN, password)
	if err != nil {
		common.SysLog(fmt.Sprintf("LDAP authentication failed for user %s: %v", username, err))
		return false, nil
	}

	common.SysLog(fmt.Sprintf("LDAP authentication successful for user: %s", username))
	return true, nil
}

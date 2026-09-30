package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercise the real LDAP client against a controlled TCP directory boundary.
// Only directory search and password bind responses are simulated.
func setupLDAPLoginTest(t *testing.T, entries int) (*model.User, <-chan *ber.Packet) {
	t.Helper()
	user, _ := setupSecurityEnrollmentTest(t)
	previousEnabled, previousURL := common.LDAPEnabled, common.LDAPServerURL
	previousDN, previousPassword := common.LDAPBindDN, common.LDAPBindPassword
	previousBase, previousFilter := common.LDAPBaseDN, common.LDAPUserFilter
	previousRegistration, previousSecure := common.RegisterEnabled, common.SessionCookieSecure
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	common.LDAPEnabled, common.LDAPServerURL = true, "ldap://"+listener.Addr().String()
	common.LDAPBindDN, common.LDAPBindPassword = "", ""
	common.LDAPBaseDN, common.LDAPUserFilter = "dc=example,dc=test", "(uid=%s)"
	common.RegisterEnabled, common.SessionCookieSecure = false, false
	filters := make(chan *ber.Packet, 8)
	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer conn.Close()
				for {
					packet, err := ber.ReadPacket(conn)
					if err != nil {
						return
					}
					id := packet.Children[0].Value.(int64)
					request := packet.Children[1]
					switch request.Tag {
					case 0: // BindRequest
						code := int64(0)
						if string(request.Children[2].Data.Bytes()) != "directory-password" {
							code = 49 // invalidCredentials
						}
						_, err = conn.Write(ldapTestResult(id, 1, code).Bytes())
					case 3: // SearchRequest
						filters <- request.Children[6]
						for range entries {
							response := ber.NewSequence("")
							response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
							entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
							entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=directory-user,dc=example,dc=test", ""))
							entry.AppendChild(ber.NewSequence(""))
							response.AppendChild(entry)
							if _, err = conn.Write(response.Bytes()); err != nil {
								return
							}
						}
						_, err = conn.Write(ldapTestResult(id, 5, 0).Bytes())
					case 2: // UnbindRequest
						return
					default:
						t.Errorf("unexpected LDAP operation %d", request.Tag)
						return
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		connections.Wait()
		common.LDAPEnabled, common.LDAPServerURL = previousEnabled, previousURL
		common.LDAPBindDN, common.LDAPBindPassword = previousDN, previousPassword
		common.LDAPBaseDN, common.LDAPUserFilter = previousBase, previousFilter
		common.RegisterEnabled, common.SessionCookieSecure = previousRegistration, previousSecure
	})
	return user, filters
}

func ldapTestResult(id int64, tag ber.Tag, code int64) *ber.Packet {
	packet := ber.NewSequence("")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	packet.AppendChild(result)
	return packet
}

func ldapLoginRequest(t *testing.T, credentials map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := common.Marshal(credentials)
	require.NoError(t, err)
	router := gin.New()
	router.POST("/api/user/login/ldap", middleware.SessionCookieOriginGuard(), LDAPLogin)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/user/login/ldap", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	return response
}

func TestLDAPLoginIssuesBrowserSessionAndLDAPAudit(t *testing.T) {
	user, _ := setupLDAPLoginTest(t, 1)
	response := ldapLoginRequest(t, map[string]string{"username": user.Username, "password": "directory-password"})
	var result struct {
		Success bool               `json:"success"`
		Data    service.AuthBundle `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
	require.True(t, result.Success)
	assert.Equal(t, "ldap", result.Data.Session.LoginMethod)
	identity, err := service.ParseAccessToken(result.Data.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.Id, identity.UserID)
	var audit model.AuditLog
	require.NoError(t, model.LOG_DB.Where("category = ?", model.AuditCategoryLogin).Last(&audit).Error)
	assert.Equal(t, "ldap", audit.Other.LoginMethod)
	assert.NotContains(t, response.Body.String(), "directory-password")
	assert.NotContains(t, response.Body.String(), user.Password)
	var refreshCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == service.RefreshCookieName {
			refreshCookie = cookie
		}
	}
	require.NotNil(t, refreshCookie)
	assert.True(t, refreshCookie.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, refreshCookie.SameSite)
}

func TestLDAPLoginRejectsCredentialsAndInactiveUsersWithoutIssuingSessions(t *testing.T) {
	for _, scenario := range []string{"bad password", "unknown user", "ambiguous directory", "disabled user", "LDAP disabled", "plaintext encryption bypass", "missing password"} {
		t.Run(scenario, func(t *testing.T) {
			entries := 1
			if scenario == "unknown user" {
				entries = 0
			}
			if scenario == "ambiguous directory" {
				entries = 2
			}
			user, _ := setupLDAPLoginTest(t, entries)
			password := "directory-password"
			switch scenario {
			case "bad password":
				password = "wrong-password"
			case "disabled user":
				require.NoError(t, model.DB.Model(user).Update("status", common.UserStatusDisabled).Error)
			case "LDAP disabled":
				common.LDAPEnabled = false
			case "plaintext encryption bypass":
				common.PasswordLoginEncryptionEnabled = true
			case "missing password":
				password = ""
			}
			response := ldapLoginRequest(t, map[string]string{"username": user.Username, "password": password})
			var result struct {
				Success bool `json:"success"`
			}
			require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
			assert.False(t, result.Success)
			assert.Empty(t, response.Header().Values("Set-Cookie"))
			count, err := model.CountActiveUserSessions(user.Id, time.Now().Unix())
			require.NoError(t, err)
			assert.EqualValues(t, 1, count, "only the fixture's existing session may remain")
		})
	}
}

func TestLDAPLoginRequiresSharedMFAAndRejectsExpiredOrReplayedVerification(t *testing.T) {
	for _, scenario := range []string{"complete and replay", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			user, _ := setupLDAPLoginTest(t, 1)
			secret := "JBSWY3DPEHPK3PXP"
			require.NoError(t, model.DB.Create(&model.TwoFA{UserId: user.Id, Secret: secret, IsEnabled: true}).Error)
			response := ldapLoginRequest(t, map[string]string{"username": user.Username, "password": "directory-password"})
			var result struct {
				Success bool                   `json:"success"`
				Data    service.LoginChallenge `json:"data"`
			}
			require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
			require.True(t, result.Success)
			require.True(t, result.Data.RequireVerification)
			assert.Empty(t, response.Header().Values("Set-Cookie"))
			count, err := model.CountActiveUserSessions(user.Id, time.Now().Unix())
			require.NoError(t, err)
			assert.EqualValues(t, 1, count)
			if scenario == "expired" {
				require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", model.AuthFlowPurposeLoginVerification).Update("expires_at", time.Now().Add(-time.Minute)).Error)
			}
			code, err := totp.GenerateCode(secret, time.Now())
			require.NoError(t, err)
			body, err := common.Marshal(map[string]string{"flow_token": result.Data.FlowToken, "method": "2fa", "code": code})
			require.NoError(t, err)
			verified := securityEnrollmentRequest("POST", "/api/user/login/verify", string(body), "", service.AuthIdentity{}, VerifyLogin)
			var completed struct {
				Success bool               `json:"success"`
				Data    service.AuthBundle `json:"data"`
			}
			require.NoError(t, common.Unmarshal(verified.Body.Bytes(), &completed))
			if scenario == "expired" {
				assert.False(t, completed.Success)
				assert.Empty(t, verified.Header().Values("Set-Cookie"))
				return
			}
			require.True(t, completed.Success)
			assert.Equal(t, "ldap", completed.Data.Session.LoginMethod)
			replayed := securityEnrollmentRequest("POST", "/api/user/login/verify", string(body), "", service.AuthIdentity{}, VerifyLogin)
			require.NoError(t, common.Unmarshal(replayed.Body.Bytes(), &completed))
			assert.False(t, completed.Success)
			assert.Empty(t, replayed.Header().Values("Set-Cookie"))
		})
	}
}

func TestLDAPLoginEncryptedPasswordUsesDirectoryAuthentication(t *testing.T) {
	user, _ := setupLDAPLoginTest(t, 1)
	privateKey, err := common.GeneratePasswordEncryptionPrivateKey()
	require.NoError(t, err)
	require.NoError(t, common.LoadPasswordEncryptionPrivateKey(privateKey))
	keyID, publicPEM := common.PasswordEncryptionPublicKey()
	block, _ := pem.Decode([]byte(publicPEM))
	require.NotNil(t, block)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey.(*rsa.PublicKey), []byte("directory-password"), nil)
	require.NoError(t, err)
	common.PasswordLoginEncryptionEnabled = true
	response := ldapLoginRequest(t, map[string]string{"username": user.Username, "password_encrypted": base64.StdEncoding.EncodeToString(ciphertext), "encryption_key_id": keyID})
	var result struct {
		Success bool `json:"success"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
	assert.True(t, result.Success)
}

func TestLDAPLoginAutoRegistrationRespectsSettingAndDoesNotStoreDirectoryPassword(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "registration disabled", true: "registration enabled"}[enabled], func(t *testing.T) {
			setupLDAPLoginTest(t, 1)
			common.RegisterEnabled = enabled
			require.NoError(t, model.LOG_DB.AutoMigrate(&model.Log{}))
			response := ldapLoginRequest(t, map[string]string{"username": "new-directory-user", "password": "directory-password"})
			var result struct {
				Success bool `json:"success"`
			}
			require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
			assert.Equal(t, enabled, result.Success)
			var users []model.User
			require.NoError(t, model.DB.Where("username = ?", "new-directory-user").Find(&users).Error)
			if !enabled {
				assert.Empty(t, users)
				return
			}
			require.Len(t, users, 1)
			assert.Empty(t, users[0].Password)
			assert.Equal(t, common.RoleCommonUser, users[0].Role)
		})
	}
}

func TestLDAPLoginEscapesFilterAndRejectsCrossOriginSimpleRequests(t *testing.T) {
	_, filters := setupLDAPLoginTest(t, 0)
	input := "*)(uid=*)"
	ldapLoginRequest(t, map[string]string{"username": input, "password": "directory-password"})
	filter := <-filters
	assert.EqualValues(t, 3, filter.Tag, "search must remain a single equality assertion")
	require.Len(t, filter.Children, 2)
	assert.Equal(t, input, string(filter.Children[1].Data.Bytes()))
	for _, scenario := range []string{"simple content type", "foreign origin"} {
		t.Run(scenario, func(t *testing.T) {
			common.SessionCookieSecure = scenario == "foreign origin"
			router := gin.New()
			router.POST("/api/user/login/ldap", middleware.SessionCookieOriginGuard(), LDAPLogin)
			response := httptest.NewRecorder()
			request := httptest.NewRequest("POST", "https://example.com/api/user/login/ldap", strings.NewReader(`{"username":"directory-user","password":"directory-password"}`))
			request.Header.Set("Content-Type", "text/plain")
			if scenario == "foreign origin" {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", "https://evil.example")
			}
			router.ServeHTTP(response, request)
			var result struct {
				Success bool `json:"success"`
			}
			require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
			assert.False(t, result.Success)
			assert.Empty(t, response.Header().Values("Set-Cookie"))
		})
	}
}

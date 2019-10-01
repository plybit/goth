// Package xero implements the OAuth2 protocol for authenticating users through xero.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package xero2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/plybit/goth"
	"golang.org/x/oauth2"
)

const (
	providerName = "xero2"

	// URL protocol and subdomain will be populated by newConfig().
	authURL         = "https://login.xero.com/identity/connect/authorize"
	tokenURL        = "https://identity.xero.com/connect/token"
	tenantsURL      = "https://api.xero.com/connections"
	endpointProfile = "https://api.xero.com/api.xro/2.0/Organisation"
)

var defaultScopes = []string{
	ScopeOpenID,
	ScopeProfile,
	ScopeEmail,
	ScopeOfflineAccess,
	ScopeAccountingSettingsRead,
}

// Provider is the implementation of `goth.Provider` for accessing xero.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	scopes       []string
}

// New creates a new xero provider and sets up important connection details.
// You should always call `xero.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: providerName,
		scopes:       scopes,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Client is HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Debug is a no-op for the xero package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks xero for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// FetchUser will go to xero and access basic information about the organization.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get organization information without accessToken", p.providerName)
	}

	// Find the tenants authorized at xero.
	tenants, err := p.fetchAuthorizedTenants(sess)
	if err != nil {
		return user, err
	}
	if len(tenants) == 0 {
		return user, errors.New("No authorized xero tenants found")
	}

	// Find the organization/tenant info from xero.
	return p.fetchTenantInformation(user, sess, tenants[0].TenantID)
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopesToStrings(scopes...)...)
	} else {
		ds := scopesToStrings(defaultScopes...)
		c.Scopes = append(c.Scopes, ds...)
	}

	return c
}

func scopesToStrings(scopes ...string) []string {
	strs := make([]string, len(scopes))
	for i := 0; i < len(scopes); i++ {
		strs[i] = string(scopes[i]) + " "
	}
	return strs
}

func (p *Provider) fetchAuthorizedTenants(sess *Session) ([]*XeroTenant, error) {
	// Find authorized xero tenants.
	req, err := http.NewRequest("GET", tenantsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sess.AccessToken))

	// Execute the request.
	response, err := p.Client().Do(req)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s responded with a %d trying to fetch authorized xero tenants information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var tenants []*XeroTenant
	if err := json.NewDecoder(bytes.NewReader(bits)).Decode(&tenants); err != nil {
		return nil, err
	}

	return tenants, err
}

func (p *Provider) fetchTenantInformation(user goth.User, sess *Session, tenantID string) (goth.User, error) {
	// Now request organization/tenant info.
	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sess.AccessToken))
	req.Header.Set("Xero-Tenant-Id", tenantID)

	// Execute the request.
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch xero tenant information", p.providerName, resp.StatusCode)
	}

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	if err := json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData); err != nil {
		return user, err
	}

	u := struct {
		Organisations []XeroOrganization
	}{}
	if err := json.NewDecoder(bytes.NewReader(bits)).Decode(&u); err != nil {
		return user, err
	}

	user.Name = u.Organisations[0].Name
	user.NickName = u.Organisations[0].LegalName
	user.UserID = u.Organisations[0].ShortCode

	return user, err
}

type XeroTenant struct {
	ID         string `json:"id,omitempty"`
	TenantID   string `json:"tenantId,omitempty"`
	TenantType string `json:"tenantType,omitempty"`
}

type XeroOrganization struct {
	Name             string `json:"Name,omitempty"`
	LegalName        string `json:"LegalName,omitempty"`
	OrganisationType string `json:"OrganisationType,omitempty"`
	CountryCode      string `json:"CountryCode,omitempty"`
	ShortCode        string `json:"ShortCode,omitempty"`
}

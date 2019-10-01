package xero2_test

import (
	"os"
	"testing"

	"github.com/plybit/goth"
	"github.com/plybit/goth/providers/xero2"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("XERO_KEY"))
	a.Equal(p.Secret, os.Getenv("XERO_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*xero2.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://login.xero.com/identity/connect/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://login.xero.com/identity/connect/authorize","AccessToken":"1234567890"}"`)
	a.NoError(err)

	s := session.(*xero2.Session)
	a.Equal(s.AuthURL, "https://login.xero.com/identity/connect/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *xero2.Provider {
	p := xero2.New(os.Getenv("XERO_KEY"), os.Getenv("XERO_SECRET"), "/foo")
	return p
}

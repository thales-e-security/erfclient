// Copyright 2018 Thales UK Limited
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package erfclient

import (
	"io/ioutil"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/stephanos/clock"
	erf "github.com/thales-e-security/erfcommon"
)

// ERFClient generates ephemeral random fingerprints for clients.
type ERFClient interface {

	// Token returns the current client fingerprint to send to the remote service.
	Token() ([]byte, error)
}

// New creates a new ERFClient, storing the token data in the specified file. The token will refresh
// every refresh seconds. If the file does not exist it will be created, provided the parent directory exists.
func New(tokenFile string, refresh uint) (ERFClient, error) {
	return newWithClock(tokenFile, refresh, clock.New())
}

// newWithClock allows callers to specify the clock, as seen by the library
func newWithClock(tokenFile string, refresh uint, clock clock.Clock) (ERFClient, error) {
	c := client{file: tokenFile, refresh: refresh, clock: clock}

	// Grab a token, to trigger file to be written
	_, err := c.Token()

	if err != nil {
		return nil, err
	}
	return &c, nil
}

// client is the implementation of ERFClient
type client struct {
	file    string
	refresh uint
	claims  *erf.ErfClaims
	jwt     []byte

	// clock can be overriden for unit testing
	clock clock.Clock
}

// Token implements ERFClient.Token.
func (c *client) Token() ([]byte, error) {

	if c.claims == nil {
		tokenBytes, err := readFile(c.file)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read token file")
		}

		if tokenBytes != nil {
			// Calls our claims.Valid() method.
			token, claims, err := erf.ParseToken(tokenBytes)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse token")
			}

			if !token.Valid {
				return nil, errors.New("failed to read token")
			}

			c.jwt = tokenBytes
			c.claims = claims
		}
	}

	if c.claims == nil || c.clock.Now().Unix() >= *c.claims.ExpiresAt {
		err := c.persistNewToken()
		if err != nil {
			return nil, errors.WithMessage(err, "failed to create new token")
		}
	}

	return c.jwt, nil
}

// readFile reads a file from disk. It returns nil if the file doesn't exist.
func readFile(file string) ([]byte, error) {

	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			// File does not exist, that's ok
			return nil, nil
		}

		// something else went wrong
		return nil, err
	}

	return ioutil.ReadFile(file)
}

// persistNewToken creates a new token, stores the JWT in a cache and writes it to disk
func (c *client) persistNewToken() error {

	now := c.clock.Now().Unix()

	newClaims := &erf.ErfClaims{
		IssuedAt:   erf.Int64Ptr(now),
		ExpiresAt:  erf.Int64Ptr(now + int64(c.refresh)),
		Subject:    erf.StringPtr(uuid.NewV4().String()),
		SequenceNo: erf.Int64Ptr(0),
		Previous:   erf.StringPtr(""),
	}

	if c.claims != nil {
		newClaims.SequenceNo = erf.Int64Ptr(*c.claims.SequenceNo + 1)
		newClaims.Previous = erf.StringPtr(*c.claims.Subject)
	}

	jwtString, err := jwt.NewWithClaims(jwt.SigningMethodNone, newClaims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return errors.WithMessage(err, "failed to create token")
	}

	err = ioutil.WriteFile(c.file, []byte(jwtString), 0600)
	if err != nil {
		return err
	}

	c.claims = newClaims
	c.jwt = []byte(jwtString)
	return nil
}

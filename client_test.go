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
	"path/filepath"
	"testing"
	"time"

	"github.com/stephanos/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	erf "github.com/thales-e-security/erfcommon"
)

func TestReadBadFile(t *testing.T) {
	res, err := readFile("this does not exist")
	assert.NoError(t, err)
	assert.Nil(t, res)
}

func TestFirstToken(t *testing.T) {
	dir, err := ioutil.TempDir("", "erf")
	require.NoError(t, err)

	defer os.RemoveAll(dir)

	f := filepath.Join(dir, "newtokenfile")

	mockClock := clock.NewMock()
	mockClock.Freeze()

	const refresh = 100
	client, err := newWithClock(f, refresh, mockClock)
	require.NoError(t, err)

	token, err := client.Token()
	require.NoError(t, err)

	_, claims, err := erf.ParseToken(token)
	require.NoError(t, err)

	assert.Equal(t, mockClock.Now().Unix(), *claims.IssuedAt)
	assert.Equal(t, mockClock.Now().Unix()+refresh, *claims.ExpiresAt)
	assert.Equal(t, "", *claims.Previous)
	assert.Equal(t, int64(0), *claims.SequenceNo)
	assert.NotEmpty(t, claims.Subject)

	client2, err := newWithClock(f, refresh, mockClock)
	require.NoError(t, err)

	token, err = client2.Token()
	require.NoError(t, err)

	_, claims2, err := erf.ParseToken(token)
	require.NoError(t, err)

	// check it is persisted and read correctly
	assert.Equal(t, claims, claims2)
}

func TestNoRollover(t *testing.T) {
	dir, err := ioutil.TempDir("", "erf")
	require.NoError(t, err)

	defer os.RemoveAll(dir)

	f := filepath.Join(dir, "newtokenfile")

	mockClock := clock.NewMock()
	mockClock.Freeze()

	const refresh = 100
	client, err := newWithClock(f, refresh, mockClock)
	require.NoError(t, err)

	token, err := client.Token()
	require.NoError(t, err)

	_, claims, err := erf.ParseToken(token)
	require.NoError(t, err)

	mockClock.Add((refresh - 1) * time.Second)
	token, err = client.Token()
	require.NoError(t, err)

	_, claims2, err := erf.ParseToken(token)
	require.NoError(t, err)

	// Should be equal, since we have not rolled over
	assert.Equal(t, claims, claims2)
}

func TestRollover(t *testing.T) {
	dir, err := ioutil.TempDir("", "erf")
	require.NoError(t, err)

	defer os.RemoveAll(dir)

	f := filepath.Join(dir, "newtokenfile")

	mockClock := clock.NewMock()
	mockClock.Freeze()

	const refresh = 100
	client, err := newWithClock(f, refresh, mockClock)
	require.NoError(t, err)

	token, err := client.Token()
	require.NoError(t, err)

	_, claims, err := erf.ParseToken(token)
	require.NoError(t, err)

	mockClock.Add(refresh * time.Second)
	token, err = client.Token()
	require.NoError(t, err)

	_, claims2, err := erf.ParseToken(token)
	require.NoError(t, err)

	// Should have rolled over
	assert.Equal(t, *claims.Subject, *claims2.Previous)
	assert.Equal(t, *claims.SequenceNo+1, *claims2.SequenceNo)
	assert.NotEqual(t, *claims.Subject, *claims2.Subject)
}

func TestProperClock(t *testing.T) {
	// ugly type check

	dir, err := ioutil.TempDir("", "erf")
	require.NoError(t, err)

	defer os.RemoveAll(dir)

	f := filepath.Join(dir, "newtokenfile")
	c, err := New(f, 10)
	require.NoError(t, err)

	if _, ok := c.(*client).clock.(clock.Clock); !ok {
		assert.Fail(t, "Wrong clock used")
	}
}

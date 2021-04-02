package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLabelsString(t *testing.T) {
	req := assert.New(t)

	l := labels{"key1": "value1", "key2": "value2"}
	req.Equal("key1=value1,key2=value2", l.String())

	req.Equal("", (&labels{}).String())
	req.Equal("", (*labels)(nil).String())
}

func TestLabelsSet(t *testing.T) {
	req := assert.New(t)

	var l labels
	req.Error(l.Set("key"))

	req.NoError(l.Set("key=value"))
	req.NoError(l.Set("key2=value=more"))
	req.Equal(2, len(l))
	req.Equal("value", l["key"])
	req.Equal("value=more", l["key2"])

	l = labels{"key1": "value1", "key2": "value2"}
	req.NoError(l.Set("key=value"))
	req.Equal(3, len(l))
	req.Equal("value", l["key"])
	req.Equal("value1", l["key1"])
	req.Equal("value2", l["key2"])
}

func TestLabelsEqual(t *testing.T) {
	req := assert.New(t)

	var l labels
	var other map[string]string
	req.True(l.Equals(map[string]string{}))
	req.True(l.Equals(l))
	req.True(l.Equals(labels{}))
	req.True(l.Equals(other))

	other = map[string]string{"key": "value"}
	req.False(l.Equals(other))

	req.NoError(l.Set("key=value"))
	req.True(l.Equals(other))

	req.NoError(l.Set("key2=value2"))
	req.NoError(l.Set("key1=value1"))
	req.True(l.Equals(map[string]string{"key": "value", "key1": "value1", "key2": "value2"}))
}

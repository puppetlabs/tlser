package main

import (
	"fmt"
	"sort"
	"strings"
)

type labels map[string]string

func (f *labels) String() string {
	if f == nil {
		return ""
	}

	strArray := make([]string, 0, len(*f))
	for k, v := range *f {
		strArray = append(strArray, k+"="+v)
	}
	sort.Strings(strArray)
	return strings.Join(strArray, ",")
}

func (f *labels) Set(value string) error {
	if *f == nil {
		*f = make(labels)
	}

	pair := strings.SplitN(value, "=", 2)
	if len(pair) != 2 {
		return fmt.Errorf("label must be in the form <label>=<value>, not %v", value)
	}
	(*f)[pair[0]] = pair[1]
	return nil
}

func (f *labels) Equals(other map[string]string) bool {
	if len(*f) != len(other) {
		return false
	}

	// Maps have equal size, so if other contains all our keys and their values match then they're equal.
	for k, v := range *f {
		if other[k] != v {
			return false
		}
	}
	return true
}

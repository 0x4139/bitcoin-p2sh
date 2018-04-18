package tests

import "testing"

func CompareError(t *testing.T, errMessage string, expected interface{}, got interface{}) {
	t.Error(
		errMessage,
		"\n",
		"Expected:\n",
		expected,
		"\n",
		"Got: \n",
		got,
	)
}

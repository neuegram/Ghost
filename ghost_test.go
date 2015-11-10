package ghost

import (
	"testing"
)

func TestRequestToken(t *testing.T) {
	param1 := "m198sOkJEn37DjqZ32lpRu76xmw288xSQ9"
	param2 := "1373209025"
	result := RequestToken(param1, param2)
	expectation := "9301c956749167186ee713e4f3a3d90446e84d8d19a4ca8ea9b4b314d1c51b7b"
	if result != expectation {
		t.Errorf("RequestToken(%q, %q) failed test. \n\n\rWant: \n\r\"%s\" \n\rGot: \n\r\"%s\" \n\n", param1, param2, expectation, result)
	}
}

func TestCalculateAge(t *testing.T) {

	var testParams = []struct {
		param       string
		expectation string
	}{
		{"1982-11-21", "33"},
		{"1999-03-13", "16"},
		{"1990-06-12", "25"},
	}

	for _, testCase := range testParams {
		result, err := CalculateAge(testCase.param)
		if err != nil {
			t.Log(err)
		}
		if result != testCase.expectation {
			t.Errorf("CalculateAge(%q) failed test. \n\n\rWant: \"%s\" Got: \"%s\"", testCase.param, testCase.expectation, result)
		}
	}
}

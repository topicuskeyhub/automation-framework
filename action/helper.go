// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/topicuskeyhub/sdk-go/models"
	"github.com/ttacon/chalk"
)

func First[T models.Linkableable](wrapper interface{ GetItems() []T }, err error) (T, error) {
	var ret T
	if err != nil {
		return ret, err
	}
	if len(wrapper.GetItems()) == 0 {
		return ret, fmt.Errorf("no records found")
	}
	return wrapper.GetItems()[0], nil
}

func Ptr[T any](val T) *T {
	return &val
}

func Self(linkable models.Linkableable) models.RestLinkable {
	for _, l := range linkable.GetLinks() {
		if *l.GetRel() == "self" {
			return l
		}
	}
	Abort(nil, "item does not have a self link")
	return nil
}

func Koppeling(linkable models.Linkableable) models.RestLinkable {
	for _, l := range linkable.GetLinks() {
		if *l.GetRel() == "koppeling" {
			return l
		}
	}
	Abort(nil, "item does not have a koppeling link")
	return nil
}

func Abort(action AutomationAction, format string, v ...any) {
	if action == nil {
		fmt.Fprintf(os.Stderr, "\n\n%serror: %s%s\n", chalk.Red, fmt.Sprintf(format, v...), chalk.Reset)
	} else {
		fmt.Fprintf(os.Stderr, "\n\n%serror in %s: %s%s\n", chalk.Red, action.String(), fmt.Sprintf(format, v...), chalk.Reset)
	}
	os.Exit(1)
}

func KeyHubError(err error) error {
	report, ok := err.(models.ErrorReportable)
	if !ok {
		return err
	}
	var msg string
	if report.GetApplicationError() == nil {
		msg = fmt.Sprintf("Error %d from backend: %s", *report.GetCode(), stringPointerToString(report.GetMessage()))
	} else if report.GetApplicationErrorParameters() == nil {
		msg = fmt.Sprintf("Error %d (%s) from backend: %s", *report.GetCode(), *report.GetApplicationError(), stringPointerToString(report.GetMessage()))
	} else {
		msg = fmt.Sprintf("Error %d (%s:%v) from backend: %s", *report.GetCode(), *report.GetApplicationError(),
			filterErrorParameters(report.GetApplicationErrorParameters().GetAdditionalData()), stringPointerToString(report.GetMessage()))
	}
	if report.GetStacktrace() != nil {
		msg = msg + "\n" + strings.Join(report.GetStacktrace(), "\n")
	}
	return errors.New(msg)
}

func filterErrorParameters(params map[string]any) map[string]string {
	ret := make(map[string]string)
	for k, v := range params {
		if str, ok := v.(*string); ok {
			ret[k] = *str
		}
	}
	return ret
}

func stringPointerToString(input *string) string {
	if input != nil {
		return *input
	}
	return ""
}

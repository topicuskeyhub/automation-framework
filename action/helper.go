// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"fmt"
	"os"

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

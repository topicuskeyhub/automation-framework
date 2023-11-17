// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"fmt"
	"log"

	"github.com/topicuskeyhub/sdk-go/models"
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
	log.Fatalf("item does not have a self link")
	return nil
}

func Koppeling(linkable models.Linkableable) models.RestLinkable {
	for _, l := range linkable.GetLinks() {
		if *l.GetRel() == "koppeling" {
			return l
		}
	}
	log.Fatalf("item does not have a koppeling link")
	return nil
}

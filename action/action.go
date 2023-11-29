// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"context"
	"fmt"
)

const Account3UUIDPlaceholder = "00000000-0000-0000-0000-000000000000"

type AutomationAction interface {
	TypeID() string
	Parameters() []*string
	Init(ctx context.Context, env *Environment)
	IsSatisfied() bool
	Requires3() bool
	AllowGlobalOptimization() bool
	Execute(ctx context.Context, env *Environment) error
	Setup(env *Environment) []AutomationAction
	Perform(env *Environment) []AutomationAction
	Revert() AutomationAction
	Progress() string
	fmt.Stringer
}

func IsEqual(a AutomationAction, b AutomationAction) bool {
	if a.TypeID() != b.TypeID() {
		return false
	}
	ap := a.Parameters()
	bp := b.Parameters()
	if len(ap) != len(bp) {
		return false
	}
	for i := 0; i < len(ap); i++ {
		apv := ap[i]
		bpv := bp[i]
		if apv == nil || bpv == nil {
			continue
		}
		if *apv != *bpv {
			return false
		}
	}
	return true
}

func IsInverse(a AutomationAction, b AutomationAction) bool {
	revert := a.Revert()
	return revert != nil && IsEqual(revert, b)
}

func IsEqualOrInverse(a AutomationAction, b AutomationAction) bool {
	return IsEqual(a, b) || IsInverse(a, b)
}

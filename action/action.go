// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"context"
	"fmt"
	"slices"
)

type AutomationAction interface {
	TypeID() string
	Parameters() []string
	Init(ctx context.Context, env Environment)
	IsSatisfied() bool
	Execute(ctx context.Context, env Environment)
	Setup(env Environment) []AutomationAction
	Perform(env Environment) []AutomationAction
	Revert() AutomationAction
	fmt.Stringer
}

func IsEqual(a AutomationAction, b AutomationAction) bool {
	return a.TypeID() == b.TypeID() && slices.Equal(a.Parameters(), b.Parameters())
}

func IsInverse(a AutomationAction, b AutomationAction) bool {
	return IsEqual(a.Revert(), b)
}

func IsEqualOrInverse(a AutomationAction, b AutomationAction) bool {
	return IsEqual(a, b) || IsInverse(a, b)
}

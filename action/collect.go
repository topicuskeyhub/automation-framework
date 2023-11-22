// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"context"
	"slices"
)

type Stepper interface {
	Add(num int) error
}

func Collect(ctx context.Context, action AutomationAction, env *Environment, stepper Stepper) []AutomationAction {
	action.Init(ctx, env)
	ret := make([]AutomationAction, 0)
	ret = traverse(ctx, action, env, stepper, ret)
	ret = deleteInverses(ret)
	ret = deleteDuplicates(ret)
	return ret
}

func traverse(ctx context.Context, action AutomationAction, env *Environment, stepper Stepper, result []AutomationAction) []AutomationAction {
	if action.IsSatisfied() {
		return result
	}
	cleanup := make([]AutomationAction, 0)
	for _, a := range action.Setup(env) {
		stepper.Add(1)
		a.Init(ctx, env)
		if !a.IsSatisfied() {
			result = traverse(ctx, a, env, stepper, result)
			cleanup = append(cleanup, a.Revert())
		}
	}
	result = append(result, action)
	for _, a := range action.Perform(env) {
		stepper.Add(1)
		a.Init(ctx, env)
		result = traverse(ctx, a, env, stepper, result)
	}
	slices.Reverse(cleanup)
	for _, a := range cleanup {
		stepper.Add(1)
		a.Init(ctx, env)
		result = traverse(ctx, a, env, stepper, result)
	}
	return result
}

func deleteInverses(actions []AutomationAction) []AutomationAction {
	ret := actions
	for i1 := 0; i1 < len(ret); i1++ {
		v1 := ret[i1]
		i2 := slices.IndexFunc(ret[i1+1:], func(v2 AutomationAction) bool {
			return IsEqualOrInverse(v1, v2)
		})
		if i2 != -1 {
			i2 += i1
			v2 := ret[i2]
			i3 := slices.IndexFunc(ret[i2+1:], func(v3 AutomationAction) bool {
				return IsInverse(v2, v3)
			})
			if i3 != -1 {
				i3 += i2
				ret = slices.Delete(ret, i2, i2)
				ret = slices.Delete(ret, i3, i3)
			}
		}
	}
	return ret
}

func deleteDuplicates(actions []AutomationAction) []AutomationAction {
	ret := actions
	for i := 0; i < len(ret); i++ {
		v := ret[i]
		ret = slices.DeleteFunc(ret[i+1:], func(v2 AutomationAction) bool {
			return IsEqual(v, v2)
		})
	}
	return ret
}

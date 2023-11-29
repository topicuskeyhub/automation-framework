// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"context"
	"slices"
)

type Stepper interface {
	Step()
	AddSteps(num int64)
	Done()
}

func Collect(ctx context.Context, action AutomationAction, env *Environment, stepper Stepper) []AutomationAction {
	action.Init(ctx, env)
	ret := make([]AutomationAction, 0)
	ret = traverse(ctx, action, false, env, stepper, ret)
	printActions(ret)
	ret = deleteInverses(ret)
	return ret
}

func addSteps(stepper Stepper, steps []AutomationAction) []AutomationAction {
	stepper.AddSteps(int64(len(steps)))
	return steps
}

func addStep(stepper Stepper, step AutomationAction) AutomationAction {
	if step != nil {
		stepper.AddSteps(1)
	}
	return step
}

func traverse(ctx context.Context, action AutomationAction, force bool, env *Environment, stepper Stepper, result []AutomationAction) []AutomationAction {
	if !force && action.IsSatisfied() {
		return result
	}
	cleanup := make([]AutomationAction, 0)
	for _, a := range addSteps(stepper, action.Setup(env)) {
		stepper.Step()
		a.Init(ctx, env)
		if !a.IsSatisfied() {
			result = traverse(ctx, a, false, env, stepper, result)
			revert := addStep(stepper, a.Revert())
			if revert != nil {
				cleanup = append(cleanup, revert)
			}
		}
	}
	result = append(result, action)
	for _, a := range addSteps(stepper, action.Perform(env)) {
		stepper.Step()
		a.Init(ctx, env)
		result = traverse(ctx, a, force, env, stepper, result)
	}
	slices.Reverse(cleanup)
	for _, a := range cleanup {
		stepper.Step()
		a.Init(ctx, env)
		result = traverse(ctx, a, true, env, stepper, result)
	}
	return result
}

func deleteInverses(actions []AutomationAction) []AutomationAction {
	ret := actions
	for i1 := 0; i1 < len(ret)-1; i1++ {
		if ret[i1].AllowGlobalOptimization() {
			for i2 := i1 + 1; i2 < len(ret); i2++ {
				if IsInverse(ret[i1], ret[i2]) {
					ret = slices.Delete(ret, i2, i2+1)
					ret = slices.Delete(ret, i1, i1+1)
					i1 = i1 - 2
					if i1 < -1 {
						i1 = -1
					}
					break
				}
			}
		} else {
			if IsInverse(ret[i1], ret[i1+1]) {
				ret = slices.Delete(ret, i1, i1+2)
				i1 = i1 - 2
				if i1 < -1 {
					i1 = -1
				}
			}
		}
	}
	return ret
}

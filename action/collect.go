// Copyright (c) Topicus Security B.V.
// SPDX-License-Identifier: APSL-2.0

package action

import (
	"context"
	"fmt"
	"os"
	"slices"
)

type Stepper interface {
	Step()
	AddSteps(num int64)
	Done()
}

func Collect(ctx context.Context, action AutomationAction, env *Environment, stepper Stepper) []AutomationAction {
	var err error
	action.Init(ctx, env)
	ret := make([]AutomationAction, 0)
	ret, err = traverse(ctx, 1, action, false, env, stepper, ret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
		return nil
	}
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

func traverse(ctx context.Context, depth int, action AutomationAction, force bool, env *Environment, stepper Stepper, result []AutomationAction) ([]AutomationAction, error) {
	if !force && action.IsSatisfied() {
		return result, nil
	}
	if depth > 20 {
		return nil, fmt.Errorf("maximum depth of 20 exceeded:\n  at %s", action.String())
	}

	var err error
	ret := result
	cleanup := make([]AutomationAction, 0)
	for _, a := range addSteps(stepper, action.Setup(env)) {
		stepper.Step()
		a.Init(ctx, env)
		if !a.IsSatisfied() {
			ret, err = traverse(ctx, depth+1, a, false, env, stepper, ret)
			if err != nil {
				return nil, fmt.Errorf("%s\n  at %s", err, action.String())
			}
			revert := addStep(stepper, a.Revert())
			if revert != nil {
				cleanup = append(cleanup, revert)
			}
		}
	}
	ret = append(ret, action)
	for _, a := range addSteps(stepper, action.Perform(env)) {
		stepper.Step()
		a.Init(ctx, env)
		ret, err = traverse(ctx, depth+1, a, force, env, stepper, ret)
		if err != nil {
			return nil, fmt.Errorf("%s\n  at %s", err, action.String())
		}
	}
	slices.Reverse(cleanup)
	for _, a := range cleanup {
		stepper.Step()
		a.Init(ctx, env)
		ret, err = traverse(ctx, depth+1, a, true, env, stepper, ret)
		if err != nil {
			return nil, fmt.Errorf("%s\n  at %s", err, action.String())
		}
	}
	return ret, nil
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

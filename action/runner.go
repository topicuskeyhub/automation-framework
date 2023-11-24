package action

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aquilax/truncate"
	"github.com/manifoldco/promptui"
	"github.com/schollz/progressbar/v3"
)

func buildProgressBar(max int64, desc string) *progressbar.ProgressBar {
	return progressbar.NewOptions64(
		max,
		progressbar.OptionSetDescription(desc),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(50),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowDescriptionAtLineEnd(),
		progressbar.OptionSetItsString("steps"),
	)
}

func executeAction(ctx context.Context, action AutomationAction, env *Environment) {
	err := action.Execute(ctx, env)
	if err != nil {
		fmt.Printf("\n\nAn error occured during execution of %s: %s", action.String(), err)
		prompt := promptui.Select{
			Label: "How do you want to continue",
			Items: []string{"Retry", "Continue", "Abort"},
		}
		i, _, err := prompt.Run()
		if err != nil {
			Abort(action, "Select aborted: %s", err)
		} else if i == 0 {
			fmt.Printf("Retrying action\n")
			executeAction(ctx, action, env)
		} else if i == 1 {
			fmt.Printf("Continuing with the next action\n")
		} else if i == 2 {
			Abort(action, "Aborting automation")
		}
	}
}

func printActions(actions []AutomationAction) {
	fmt.Printf("The following steps will be performed:\n")
	for _, a := range actions {
		fmt.Printf(" - %s\n", a.String())
	}
}

func Run(config AuthenticationConfig, action AutomationAction) {
	ctx := context.Background()
	env, err := SetupEnvironment(ctx, config)
	if err != nil {
		Abort(action, "unable to authenticate to Topicus KeyHub: %s", err)
		return
	}
	fmt.Printf("Collecting actions for %s...\n", action.String())
	bar := buildProgressBar(-1, "collecting")
	actions := Collect(ctx, action, env, bar)
	bar.Finish()

	printActions(actions)

	prompt := promptui.Prompt{
		Label:     "Do you want to continue",
		IsConfirm: true,
	}
	_, err = prompt.Run()
	if err != nil {
		Abort(action, "Aborting automation")
		return
	}

	bar = buildProgressBar(int64(len(actions)), "Starting")
	for _, a := range actions {
		bar.Describe(truncate.Truncate(a.Progress(), 40, truncate.DEFAULT_OMISSION, truncate.PositionEnd))
		bar.Add(1)
		executeAction(ctx, a, env)
	}
	bar.Finish()
}

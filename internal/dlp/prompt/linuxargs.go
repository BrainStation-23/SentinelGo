package prompt

// The Linux dialogs' command lines and how their answers read, without the
// tools themselves (prompt_linux.go only runs them), so they are tested on
// every platform.

const (
	flagTitle    = "--title"
	reasonTitled = "--text="
)

// singleLabel is the one button offered when only one choice is possible.
func singleLabel(a Ask) string {
	if a.CanOverride {
		return labelOverride
	}
	return labelRequest
}

// zenityQuestionArgs asks which choice: OK is the first available choice,
// the extra button the request when both are possible.
func zenityQuestionArgs(a Ask) []string {
	args := []string{"--question", flagTitle + "=" + a.Title, reasonTitled + a.Message,
		"--cancel-label=" + labelCancel, "--ok-label=" + singleLabel(a)}
	if a.CanOverride && a.CanRequest {
		args = append(args, "--extra-button="+labelRequest)
	}
	return args
}

// zenityReasonArgs asks for the reason.
func zenityReasonArgs(a Ask) []string {
	return []string{"--entry", flagTitle + "=" + a.Title, reasonTitled + reasonPrompt}
}

// zenityAnswer reads the question's exit code and output as a choice.
func zenityAnswer(a Ask, code int, out string) string {
	choice := zenityChoice(code, out)
	if !a.CanOverride && choice == ChoiceOverride {
		return ChoiceRequest // OK was the request button
	}
	return choice
}

// kdialogQuestionArgs asks which choice: yes/no/cancel when both choices
// are possible, else yes/no with the one choice as yes.
func kdialogQuestionArgs(a Ask) []string {
	if a.CanOverride && a.CanRequest {
		return []string{flagTitle, a.Title, "--yesnocancel", a.Message,
			"--yes-label", labelOverride, "--no-label", labelRequest, "--cancel-label", labelCancel}
	}
	return []string{flagTitle, a.Title, "--yesno", a.Message, "--yes-label", singleLabel(a), "--no-label", labelCancel}
}

// kdialogReasonArgs asks for the reason.
func kdialogReasonArgs(a Ask) []string {
	return []string{flagTitle, a.Title, "--inputbox", reasonPrompt}
}

// kdialogAnswer reads the question's exit code as a choice.
func kdialogAnswer(a Ask, code int) string {
	if a.CanOverride && a.CanRequest {
		return kdialogChoice(code)
	}
	if code != 0 {
		return ChoiceCancel
	}
	if a.CanOverride {
		return ChoiceOverride
	}
	return ChoiceRequest
}

package result

type Result struct {
	Rule    string
	Type    string
	Message string
	Details map[string]any
}

package section

//Intersect returns true if a and b are overlapping
func Intersect(a, b Interval) bool {
	//case1: both intervals are points => compare with equality
	if a.Begin() == a.End() && b.Begin() == b.End() && a.Begin() != "" && b.Begin() != "" {
		return a.Begin() == b.Begin()
	}
	//case2: at least one of them is an interval
	if a.Begin() == "" {
		return b.Begin() == "" || a.End() == "" || a.End() > b.Begin()
	}
	if a.End() == "" {
		return b.End() == "" || a.Begin() < b.End()
	}
	if b.Begin() == "" {
		return b.End() == "" || b.End() > a.Begin()
	}
	if b.End() == "" {
		return b.Begin() < a.End()
	}
	return a.Begin() < b.End() && a.End() > b.Begin()
}

//TotalInterval is an interval over the whole namespace
type TotalInterval struct{}

//Begin defines the start of the total namespace
func (t TotalInterval) Begin() string {
	return ""
}

//End defines the end of the total namespace
func (t TotalInterval) End() string {
	return ""
}

//StringInterval implements Interval for a single string value
type StringInterval struct {
	Name string
}

//Begin defines the start of a StringInterval namespace
func (s StringInterval) Begin() string {
	return s.Name
}

//End defines the end of a StringInterval namespace
func (s StringInterval) End() string {
	return s.Name
}

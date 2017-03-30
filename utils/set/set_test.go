package set

import (
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	set1 := New()
	if set1.isDeleted {
		t.Errorf("Newly created set is already deleted. isDeleted=%v", set1.isDeleted)
	}
	if set1.data == nil || len(set1.data) > 0 {
		t.Errorf("Data map not correctly initialized. data:%v", set1.data)
	}
	set2 := New()
	if set1 == set2 {
		t.Errorf("New did not create a new instance, %v == %v", set1, set2)
	}
}

type structWithPointer struct {
	validity int
	ptr      *int
}

func TestAdd(t *testing.T) {
	//test if added value is stored correctly in the set
	set := New()
	set.Add(5)
	if !set.data[5] {
		t.Errorf("Inserted value not contained. %v", set.data)
	}
	set = New()
	set.Add("Test")
	if !set.data["Test"] {
		t.Errorf("Inserted value not contained. %v", set.data)
	}
	set = New()
	integer := 5
	input := structWithPointer{validity: 10, ptr: &integer}
	set.Add(input)
	if !set.data[input] {
		t.Errorf("Inserted value not contained. %v", set.data)
	}
	//"concurrency test"
	set = New()
	var wg sync.WaitGroup
	runs := 1000
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go addValue(i, set, &wg)
	}
	wg.Wait()
	if len(set.data) != runs {
		t.Error("Race condition: some data was not added to the set.")
	}
	//do not add data after deleted flag is set and return false
	set = New()
	if ok := set.Add(5); !ok {
		t.Errorf("Add returns not delete flag. flag=%v, returnvalue=%v", set.isDeleted, ok)
	}
	set.isDeleted = true
	if ok := set.Add(6); ok || len(set.data) != 1 {
		t.Errorf("Add still works after delete flag is set.")
	}
}

func addValue(i int, set *Set, wg *sync.WaitGroup) {
	set.Add(i)
	wg.Done()
}

func TestDelete(t *testing.T) {
	//test if deletion deletes the specified value
	set := New()
	set.data[5] = true
	set.Delete(5)
	if len(set.data) != 0 {
		t.Errorf("Delete did not work. %v", set.data)
	}
	set = New()
	set.data[5] = true
	set.data[6] = true
	set.Delete(5)
	if !set.data[6] || set.data[5] {
		t.Errorf("Delete did not work. %v", set.data)
	}
	//check that deleting a non existing value does not result in a panic
	set = New()
	set.data[5] = true
	set.Delete(7)
	if !set.data[5] {
		t.Errorf("Delete did not work. %v", set.data)
	}
	//"concurrency test"
	set = New()
	var wg sync.WaitGroup
	runs := 1000
	for i := 0; i < runs; i++ {
		set.data[i] = true
	}
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go deleteValue(i, set, &wg)
	}
	wg.Wait()
	if len(set.data) != 0 {
		t.Error("Race condition: some data was not deleted from the set.")
	}
}

func deleteValue(i int, set *Set, wg *sync.WaitGroup) {
	set.Delete(i)
	wg.Done()
}

func TestGetAll(t *testing.T) {
	set := New()
	checkAllContained(set, t, set.GetAll)
	if set.isDeleted {
		t.Error("Deleted flag must not be set")
	}
	//return empty slice if deleted flag is set.
	set.isDeleted = true
	if l := set.GetAll(); len(l) != 0 {
		t.Errorf("GetAll returns values although deleted flag is set. Returned %v", l)
	}
}

func TestGetAllAndDelete(t *testing.T) {
	//check that all contained elements are returned by getAll
	set := New()
	checkAllContained(set, t, set.GetAllAndDelete)
	if !set.isDeleted {
		t.Error("Deleted flag was not set")
	}
	set.isDeleted = true
	if l := set.GetAllAndDelete(); len(l) != 0 {
		t.Errorf("GetAllAndDelete returns values although deleted flag is set. Returned %v", l)
	}
}

//checkAllContained checks that all contained elements are returned by getAll
func checkAllContained(set *Set, t *testing.T, function func() []interface{}) {
	runs := 10
	for i := 0; i < runs; i++ {
		set.data[i] = true
	}
	funcReturn := function()
	if len(funcReturn) != runs {
		t.Errorf("Number of entries do not match. Want=%v, returned by len(function())=%v", runs, len(funcReturn))
	}
	checkMap := make(map[int]bool)
	for i := 0; i < runs; i++ {
		checkMap[i] = false
	}
	for _, v := range funcReturn {
		checkMap[v.(int)] = true
	}
	for i, v := range checkMap {
		if !v {
			t.Errorf("Not all entries are returned. Entry %d not returned", i)
		}
	}
}

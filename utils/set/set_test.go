package set

import (
	"fmt"
	"sync"
	"testing"

	"github.com/netsec-ethz/rains/rainslib"
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

func (s structWithPointer) Hash() string {
	return fmt.Sprintf("%d_%v", s.validity, s.ptr)
}

func TestAdd(t *testing.T) {
	//test if added value is stored correctly in the set
	set := New()
	v := structWithPointer{validity: 5}
	set.Add(v)
	if _, ok := set.data[v.Hash()]; !ok {
		t.Errorf("Inserted value not contained. %v", set.data)
	}
	set = New()
	integer := 5
	input := structWithPointer{validity: 10, ptr: &integer}
	set.Add(input)
	if _, ok := set.data[input.Hash()]; !ok {
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
	if ok := set.Add(v); !ok {
		t.Errorf("Add returns not delete flag. flag=%v, returnvalue=%v", set.isDeleted, ok)
	}
	set.isDeleted = true
	newValue := structWithPointer{validity: 6}
	if ok := set.Add(newValue); ok || len(set.data) != 1 {
		t.Errorf("Add still works after delete flag is set.")
	}
}

func addValue(i int, set *Set, wg *sync.WaitGroup) {
	set.Add(structWithPointer{validity: i})
	wg.Done()
}

func TestDelete(t *testing.T) {
	//test if deletion deletes the specified value
	set := New()
	v := structWithPointer{validity: 5}
	v2 := structWithPointer{validity: 6}
	v3 := structWithPointer{validity: 7}
	set.data[v.Hash()] = v
	ok := set.Delete(v)
	if len(set.data) != 0 {
		t.Errorf("Delete did not work. %v", set.data)
	}
	if !ok {
		t.Errorf("Wrong return value=%v", ok)
	}
	set = New()
	set.data[v.Hash()] = v
	set.data[v2.Hash()] = v2
	ok = set.Delete(v)
	_, ok2 := set.data[v.Hash()]
	if !ok || ok2 {
		t.Errorf("Delete did not work. %v, ok=%v, ok2=%v", set.data, ok, ok2)
	}
	if !ok {
		t.Errorf("Wrong return value=%v", ok)
	}
	//check that deleting a non existing value does not result in a panic and that return value is correct
	set = New()
	set.data[v.Hash()] = v
	ok = set.Delete(v3)
	if ok {
		t.Errorf("Delete did not work. %v", set.data)
	}
	if ok {
		t.Errorf("Wrong return value=%v", ok)
	}
	//"concurrency test"
	set = New()
	var wg sync.WaitGroup
	runs := 1000
	for i := 0; i < runs; i++ {
		v := structWithPointer{validity: i}
		set.data[v.Hash()] = v
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
	set.Delete(structWithPointer{validity: i})
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
func checkAllContained(set *Set, t *testing.T, function func() []rainslib.Hashable) {
	runs := 10
	for i := 0; i < runs; i++ {
		v := structWithPointer{validity: i}
		set.data[v.Hash()] = v
	}
	funcReturn := function()
	if len(funcReturn) != runs {
		t.Errorf("Number of entries do not match. Want=%v, returned by len(function())=%v", runs, len(funcReturn))
	}
	checkMap := make(map[string]bool)
	for i := 0; i < runs; i++ {
		v := structWithPointer{validity: i}
		checkMap[v.Hash()] = false
	}
	for _, v := range funcReturn {
		checkMap[v.Hash()] = true
	}
	for i, v := range checkMap {
		if !v {
			t.Errorf("Not all entries are returned. Entry %s not returned", i)
		}
	}
}

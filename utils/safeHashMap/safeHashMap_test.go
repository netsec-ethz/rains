package safeHashMap

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	hashMap := New()
	hashMap2 := New()
	if hashMap == hashMap2 {
		t.Errorf("New did not create a new instance, %v == %v", hashMap, hashMap)
	}
}

func TestAdd(t *testing.T) {
	//test if added value is stored correctly in the map
	hashMap := New()
	ok := hashMap.Add("v", 5)
	if v := hashMap.hashMap["v"]; !ok || v != 5 {
		t.Errorf("Inserted value not contained or wrong. %v", hashMap.hashMap)
	}
	ok = hashMap.Add("v", 6)
	if v := hashMap.hashMap["v"]; ok || v != 6 {
		t.Errorf("Inserted value did not overwrote old value. value=%v newValue=%v", v, ok)
	}
	//"concurrency test"
	hashMap = New()
	var wg sync.WaitGroup
	runs := 100000
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go addValue(i, hashMap, &wg)
	}
	wg.Wait()
	if len(hashMap.hashMap) != runs {
		t.Errorf("Race condition: some data was not added to the map. expected=%d actual=%d", runs, len(hashMap.hashMap))
	}
}

func addValue(i int, hashMap *Map, wg *sync.WaitGroup) {
	hashMap.Add(strconv.Itoa(i), i)
	wg.Done()
}

func TestGetOrAdd(t *testing.T) {
	//test if added value is stored correctly in the map
	hashMap := New()
	v, ok := hashMap.GetOrAdd("v", 5)
	if !ok || v != 5 {
		t.Errorf("Inserted value not contained or wrong. %v", hashMap.hashMap)
	}
	v, ok = hashMap.GetOrAdd("v", 6)
	if ok || v != 5 {
		t.Errorf("Inserted value overwrote existing value. value=%v newValue=%v", v, ok)
	}
	//"concurrency test"
	hashMap = New()
	var wg sync.WaitGroup
	runs := 100000
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go getOrAddValue(i, hashMap, &wg)
	}
	wg.Wait()
	if len(hashMap.hashMap) != runs {
		t.Errorf("Race condition: some data was not added to the map. expected=%d actual=%d", runs, len(hashMap.hashMap))
	}
}

func getOrAddValue(i int, hashMap *Map, wg *sync.WaitGroup) {
	hashMap.GetOrAdd(strconv.Itoa(i), i)
	wg.Done()
}

func TestGet(t *testing.T) {
	//test if added value is stored correctly in the map
	hashMap := New()
	v, ok := hashMap.Get("v")
	if ok || v != nil {
		t.Errorf("return value is not correct for a value that is not in the map. %v", hashMap.hashMap)
	}
	hashMap.hashMap["v"] = 5
	v, ok = hashMap.Get("v")
	if !ok || v != 5 {
		t.Errorf("returned existing value is false. value=%v newValue=%v", v, ok)
	}
	//"concurrency test"
	hashMap = New()
	var wg sync.WaitGroup
	runs := 1000000
	timer2 := time.NewTimer(time.Second / 2)
	go func() {
		<-timer2.C
		t.Errorf("It took to long to execute. Get is not executed in parallel. It might be a false positive if your machine is slower.")
	}()
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go getValue(i, hashMap, &wg)
	}
	wg.Wait()
	timer2.Stop()
}

func getValue(i int, hashMap *Map, wg *sync.WaitGroup) {
	hashMap.Get(strconv.Itoa(i))
	wg.Done()
}

func TestAllGet(t *testing.T) {
	//test if added value is stored correctly in the map
	hashMap := New()
	v := hashMap.GetAll()
	if len(v) != 0 {
		t.Errorf("return value is not correct for a value that is not in the map. %v", v)
	}
	hashMap.hashMap["v"] = 5
	hashMap.hashMap["v2"] = 6
	v = hashMap.GetAll()
	if len(v) != 2 {
		t.Errorf("returned list of values has wrong length. value=%v", v)
	}
	if v[0] == 5 {
		if v[1] != 6 {
			t.Errorf("returned values are false. value=%v", v)
		}
	}
	if v[0] == 6 {
		if v[1] != 5 {
			t.Errorf("returned values are false. value=%v", v)
		}
	}
}

func TestAllGetKeys(t *testing.T) {
	//test if added value is stored correctly in the map
	hashMap := New()
	v := hashMap.GetAllKeys()
	if len(v) != 0 {
		t.Errorf("return value is not correct for a value that is not in the map. %v", v)
	}
	hashMap.hashMap["v"] = 5
	hashMap.hashMap["v2"] = 6
	v = hashMap.GetAllKeys()
	if len(v) != 2 {
		t.Errorf("returned list of values has wrong length. value=%v", v)
	}
	if v[0] == "v" {
		if v[1] != "v2" {
			t.Errorf("returned values are false. value=%v", v)
		}
	}
	if v[0] == "v2" {
		if v[1] != "v" {
			t.Errorf("returned values are false. value=%v", v)
		}
	}
}

func TestRemove(t *testing.T) {
	//test if added value is stored correctly in the map
	hashMap := New()
	hashMap.hashMap["v"] = 5
	ok := hashMap.Remove("v")
	if !ok || len(hashMap.hashMap) != 0 {
		t.Errorf("value was not deleted. %v", hashMap.hashMap)
	}
	ok = hashMap.Remove("v")
	if ok || len(hashMap.hashMap) != 0 {
		t.Errorf("no value was deleted wrong return value. %v", hashMap.hashMap)
	}
	//"concurrency test"
	hashMap = New()
	var wg sync.WaitGroup
	runs := 100000
	for i := 0; i < runs; i++ {
		hashMap.hashMap[strconv.Itoa(i)] = i
	}
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go removeValue(i, hashMap, &wg)
	}
	wg.Wait()
	if len(hashMap.hashMap) != 0 {
		t.Errorf("Race condition: some data was not added to the map. expected=%d actual=%d", 0, len(hashMap.hashMap))
	}
}

func removeValue(i int, hashMap *Map, wg *sync.WaitGroup) {
	hashMap.Remove(strconv.Itoa(i))
	wg.Done()
}

func TestLen(t *testing.T) {
	hashMap := New()
	hashMap.hashMap["d"] = 5
	if hashMap.Len() != 1 {
		t.Errorf("Wrong length. expected=%v actual=%v", len(hashMap.hashMap), hashMap.Len())
	}
	delete(hashMap.hashMap, "d")
	if hashMap.Len() != 0 {
		t.Errorf("Wrong length. expected=%v actual=%v", len(hashMap.hashMap), hashMap.Len())
	}
}

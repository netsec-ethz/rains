package lruCache

import (
	"container/list"
	"strconv"
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	lrucache := New()
	lrucache2 := New()
	if lrucache == lrucache2 {
		t.Errorf("New did not create a new instance, %v == %v", lrucache, lrucache2)
	}
}

func TestGetOrAdd(t *testing.T) {
	//test if added value is stored correctly in the cache
	cache := New()
	v, ok := cache.GetOrAdd("v", 5, true)
	if !ok || v.(int) != 5 {
		t.Errorf("Inserted value not contained or wrong. %v", cache.hashMap)
	}
	v, ok = cache.GetOrAdd("v2", 4, false)
	if !ok || v.(int) != 4 {
		t.Errorf("Inserted value not contained or wrong. %v", cache.hashMap)
	}
	v, ok = cache.GetOrAdd("v", 6, true)
	if ok || v.(int) != 5 {
		t.Errorf("If element is already contained new values are ignored. %v", cache.hashMap)
	}
	v, ok = cache.GetOrAdd("v3", 4, false)
	if !ok || v.(int) != 4 {
		t.Errorf("Inserted value not contained or wrong. %v", cache.hashMap)
	}
	if cache.lruList.Back().Value.(*entry).key != "v2" {
		t.Error("Wrong element at the back of the list")
	}
	v, ok = cache.GetOrAdd("v2", 6, false)
	if ok || v.(int) != 4 {
		t.Errorf("If element is already contained new values are ignored. %v", cache.hashMap)
	}
	if cache.lruList.Back().Value.(*entry).key != "v3" {
		t.Error("Wrong element at the back of the list")
	}
	//"concurrency test"
	cache = New()
	var wg sync.WaitGroup
	runs := 100000
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go getOrAddValue(i, cache, &wg)
	}
	wg.Wait()
	if len(cache.hashMap) != runs {
		t.Errorf("Race condition: some data was not added to the cache. expected=%d actual=%d", runs, len(cache.hashMap))
	}
}

func getOrAddValue(i int, cache *Cache, wg *sync.WaitGroup) {
	cache.GetOrAdd(strconv.Itoa(i), i, true)
	wg.Done()
}

func TestGet(t *testing.T) {
	//test if added value is stored correctly in the cache
	cache := New()
	v, ok := cache.Get("v")
	if ok || v != nil {
		t.Errorf("return value is not correct for a value that is not in the map. %v", cache.hashMap)
	}
	cache.GetOrAdd("v", 5, true)
	cache.GetOrAdd("v3", 6, true)
	if cache.internalList.Back().Value.(*entry).key != "v" {
		t.Error("Wrong element at the back of the list")
	}
	v, ok = cache.Get("v")
	if !ok || v.(int) != 5 {
		t.Errorf("returned existing value is false. value=%v newValue=%v", v, ok)
	}
	if cache.internalList.Back().Value.(*entry).key != "v3" {
		t.Error("Wrong element at the back of the list")
	}

	cache.GetOrAdd("v2", 4, false)
	cache.GetOrAdd("v4", 7, false)
	if cache.lruList.Back().Value.(*entry).key != "v2" {
		t.Error("Wrong element at the back of the list")
	}
	v, ok = cache.Get("v2")
	if !ok || v.(int) != 4 {
		t.Errorf("returned existing value is false. value=%v newValue=%v", v, ok)
	}
	if cache.lruList.Back().Value.(*entry).key != "v4" {
		t.Error("Wrong element at the back of the list")
	}
}

func getValue(i int, cache *Cache, wg *sync.WaitGroup) {
	cache.Get(strconv.Itoa(i))
	wg.Done()
}

func TestGetAll(t *testing.T) {
	cache := New()
	v := cache.GetAll()
	if len(v) != 0 {
		t.Errorf("return value is not correct when cache is empty. %v", cache.hashMap)
	}
	cache.GetOrAdd("v2", 4, false)
	cache.GetOrAdd("v4", 7, false)
	v = cache.GetAll()
	if len(v) != 2 {
		t.Errorf("return value is not correct. %v", cache.hashMap)
	}
	if v[0].(int) == 4 && v[1].(int) != 7 {
		t.Errorf("returned values are not correct. %v", cache.hashMap)
	}
	if v[0].(int) == 7 && v[1].(int) != 4 {
		t.Errorf("returned values are not correct. %v", cache.hashMap)
	}
}

func TestRemove(t *testing.T) {
	//test if added value is stored correctly in the cache
	cache := New()
	cache.GetOrAdd("v", 5, true)
	v, ok := cache.Remove("v")
	if !ok || len(cache.hashMap) != 0 || cache.internalList.Len() != 0 || cache.lruList.Len() != 0 || v.(int) != 5 {
		t.Errorf("value was not deleted. %v", cache.hashMap)
	}
	cache.GetOrAdd("v", 5, false)
	v, ok = cache.Remove("v")
	if !ok || len(cache.hashMap) != 0 || cache.internalList.Len() != 0 || cache.lruList.Len() != 0 || v.(int) != 5 {
		t.Errorf("value was not deleted. %v", cache.hashMap)
	}
	v, ok = cache.Remove("v")
	if ok || len(cache.hashMap) != 0 || cache.internalList.Len() != 0 || cache.lruList.Len() != 0 || v != nil {
		t.Errorf("no value was deleted wrong return value. %v", cache.hashMap)
	}
	//"concurrency test"
	cache = New()
	var wg sync.WaitGroup
	runs := 100000
	for i := 0; i < runs; i++ {
		cache.GetOrAdd(strconv.Itoa(i), i, true)
	}
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go removeValue(i, cache, &wg)
	}
	wg.Wait()
	if len(cache.hashMap) != 0 {
		t.Errorf("Race condition: some data was not added to the cache. expected=%d actual=%d", 0, len(cache.hashMap))
	}
}

func removeValue(i int, cache *Cache, wg *sync.WaitGroup) {
	cache.Remove(strconv.Itoa(i))
	wg.Done()
}

func TestGetLeastRecentlyUsed(t *testing.T) {
	cache := New()
	k, v := cache.GetLeastRecentlyUsed()
	if k != "" || v != nil {
		t.Errorf("Wrong least recently used value returned when no entry is in the cache. expected=(\"\",nil) actual=(%s,%v)", k, v)
	}
	cache.GetOrAdd("v", 5, false)
	cache.GetOrAdd("v2", 4, false)
	k, v = cache.GetLeastRecentlyUsed()
	if k != "v" || v.(int) != 5 {
		t.Errorf("Wrong least recently used value returned expected=(v,5) actual=(%s,%v)", k, v)
	}
	k, v = cache.GetLeastRecentlyUsed()
	if k != "v" || v.(int) != 5 { //GetLeastRecentlyUsed must not update lru list
		t.Errorf("Wrong least recently used value returned expected=(v,5) actual=(%s,%v)", k, v)
	}
	cache.Get("v")
	k, v = cache.GetLeastRecentlyUsed()
	if k != "v2" || v.(int) != 4 {
		t.Errorf("Wrong least recently used value returned expected=(v2,4) actual=(%s,%v)", k, v)
	}

}

func TestLen(t *testing.T) {
	cache := New()
	cache.hashMap["d"] = &list.Element{}
	if cache.Len() != 1 {
		t.Errorf("Wrong length. expected=%v actual=%v", len(cache.hashMap), cache.Len())
	}
	delete(cache.hashMap, "d")
	if cache.Len() != 0 {
		t.Errorf("Wrong length. expected=%v actual=%v", len(cache.hashMap), cache.Len())
	}
}

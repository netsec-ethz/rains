package cache

import (
	"container/list"
	"fmt"
	"strconv"
	"sync"
	"testing"
)

type wantNew struct {
	hasError       bool
	isAnyCacheInit bool
}

func TestNew(t *testing.T) {
	inputs := [][]interface{}{
		[]interface{}{10, "anyContext"},
		[]interface{}{10, "noAnyContext"},
		[]interface{}{10, "anyContext", "something", "not important"},
		[]interface{}{},                  //no parameters
		[]interface{}{10},                //second parameter missing
		[]interface{}{"10"},              //wrong type
		[]interface{}{10, "wrong input"}, //wrong value for second parameter
	}
	want := []wantNew{
		wantNew{hasError: false, isAnyCacheInit: true},
		wantNew{hasError: false, isAnyCacheInit: false},
		wantNew{hasError: false, isAnyCacheInit: true},
		wantNew{hasError: true},
		wantNew{hasError: true},
		wantNew{hasError: true},
		wantNew{hasError: true},
	}
	for i, input := range inputs {
		cache, err := New(input...)
		if want[i].hasError {
			if err == nil {
				t.Errorf("expected error did not happend for input:%v, error:%v ", input, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("unexpected error for input:%v, error:%v ", input, err)
			continue
		}
		if cache.maxEntries != 10 {
			t.Errorf("maxEntries should be 10 but is %d", cache.maxEntries)
		}
		if cache.onEvicted != nil {
			t.Errorf("onEvicted method is not nil: %v", cache.onEvicted)
		}
		if cache.cache == nil {
			t.Error("cache not initialized")
		}
		if want[i].isAnyCacheInit {
			if cache.cacheAnyContext == nil {
				t.Error("cacheAnyContext not initialized")
			}
		} else {
			if cache.cacheAnyContext != nil {
				t.Error("cacheAnyContext should not be initialized")
			}
		}
		if cache.list == nil {
			t.Error("list not initialized")
		}
		if cache.lruList == nil {
			t.Error("lrulist not initialized")
		}
	}
	cache, _ := New(10, "anyContext")
	cache2, _ := New(10, "anyContext")
	if cache == cache2 {
		t.Errorf("New did not create a new instance, %v == %v", cache, cache2)
	}
}

type newWithEvictInput struct {
	function func(value interface{}, key ...string)
	key      []interface{}
}

func TestNewWithEvict(t *testing.T) {
	inputs := []newWithEvictInput{
		newWithEvictInput{function: func(value interface{}, key ...string) {}, key: []interface{}{10, "anyContext"}},
		newWithEvictInput{function: func(value interface{}, key ...string) { a := 5; fmt.Println(a) }, key: []interface{}{10, "noAnyContext"}},
		newWithEvictInput{function: func(value interface{}, key ...string) {}, key: []interface{}{10, "anyContext", "something", "not important"}},
		newWithEvictInput{function: nil, key: []interface{}{""}},                //no parameters
		newWithEvictInput{function: nil, key: []interface{}{10}},                //second parameter missing
		newWithEvictInput{function: nil, key: []interface{}{"10"}},              //wrong type
		newWithEvictInput{function: nil, key: []interface{}{10, "wrong input"}}, //wrong value for second parameter
	}
	want := []wantNew{
		wantNew{hasError: false, isAnyCacheInit: true},
		wantNew{hasError: false, isAnyCacheInit: false},
		wantNew{hasError: false, isAnyCacheInit: true},
		wantNew{hasError: true},
		wantNew{hasError: true},
		wantNew{hasError: true},
		wantNew{hasError: true},
	}
	for i, input := range inputs {
		cache, err := NewWithEvict(input.function, input.key...)
		if want[i].hasError {
			if err == nil {
				t.Errorf("expected error did not happend for input:%v, error:%v ", input, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("unexpected error for input:%v, error:%v ", input, err)
			continue
		}
		if cache.onEvicted == nil {
			t.Errorf("onEvicted not initialized")
		}
		if cache.maxEntries != 10 {
			t.Errorf("maxEntries should be 10 but is %d", cache.maxEntries)
		}
		if cache.cache == nil {
			t.Error("cache not initialized")
		}
		if want[i].isAnyCacheInit {
			if cache.cacheAnyContext == nil {
				t.Error("cacheAnyContext not initialized")
			}
		} else {
			if cache.cacheAnyContext != nil {
				t.Error("cacheAnyContext should not be initialized")
			}
		}
		if cache.list == nil {
			t.Error("list not initialized")
		}
		if cache.lruList == nil {
			t.Error("lrulist not initialized")
		}
	}
	cache, _ := NewWithEvict(func(value interface{}, key ...string) {}, 10, "anyContext")
	cache2, _ := NewWithEvict(func(value interface{}, key ...string) {}, 10, "anyContext")
	if cache == cache2 {
		t.Errorf("NewWithEvict did not create a new instance, %v == %v", cache, cache2)
	}
}

type wantCheckParams struct {
	maxEntries    int
	hasAnyContext bool
	errorMsg      string
}

func TestCheckParams(t *testing.T) {
	inputs := [][]interface{}{
		[]interface{}{},
		[]interface{}{10},
		[]interface{}{"Test"},
		[]interface{}{"Test", "Hello"},
		[]interface{}{10, "anyContext"},
		[]interface{}{0, "anyContext"},
		[]interface{}{-5, "anyContext"},
		[]interface{}{1, "noAnyContext"},
		[]interface{}{1, "aoiwhf"},
	}
	want := []wantCheckParams{
		wantCheckParams{maxEntries: 0, hasAnyContext: false, errorMsg: "Not enough parameters, got 0, with values: param1=[]"},
		wantCheckParams{maxEntries: 0, hasAnyContext: false, errorMsg: "Not enough parameters, got 1, with values: param1=[10]"},
		wantCheckParams{maxEntries: 0, hasAnyContext: false, errorMsg: "Not enough parameters, got 1, with values: param1=[Test]"},
		wantCheckParams{maxEntries: 0, hasAnyContext: false, errorMsg: "Invalid maxEntries parameter:Test"},
		wantCheckParams{maxEntries: 10, hasAnyContext: true, errorMsg: ""},
		wantCheckParams{maxEntries: 0, hasAnyContext: false, errorMsg: "Invalid maxEntries parameter:0"},
		wantCheckParams{maxEntries: 0, hasAnyContext: false, errorMsg: "Invalid maxEntries parameter:-5"},
		wantCheckParams{maxEntries: 1, hasAnyContext: false, errorMsg: ""},
		wantCheckParams{maxEntries: 0, hasAnyContext: false, errorMsg: "Invalid value on second parameter (hasAnyContext): param2=aoiwhf"},
	}
	for i, input := range inputs {
		if want[i].errorMsg != "" {
			_, _, err := checkParams(input...)
			if err == nil {
				t.Errorf("No error occured on input=%v.", input)
				continue
			}
			if err.Error() != want[i].errorMsg {
				t.Errorf("Wrong error occurred on input %v: errorMsg is %s", input, err.Error())
			}
			continue
		}
		maxEntries, hasAnyContext, err := checkParams(input...)
		if err != nil {
			t.Errorf("Unexpected error occurred on input %v. error=%s", input, err.Error())
			continue
		}
		if maxEntries != want[i].maxEntries {
			t.Errorf("MaxEntries not parsed correctly on input %v. want=%d, got=%d", input, want[i].maxEntries, maxEntries)
		}
		if hasAnyContext != want[i].hasAnyContext {
			t.Errorf("hasAnyContext not parsed correctly on input %v. want=%v, got=%v", input, want[i].hasAnyContext, hasAnyContext)
		}
	}
}

func TestAdd(t *testing.T) {
	//check if it initialized correctly if not yet done and that internal value is correctly added
	cache := &Cache{}
	cache.Add("val", true, ".", "many", "keys")
	if _, ok := cache.cache[".:many:keys"]; !ok {
		t.Error("Value not added to cache")
	}
	if _, ok := cache.cacheAnyContext["many:keys"]; !ok {
		t.Error("Value not added to cacheAnyContext")
	}
	if cache.list.Front().Value.(*entry).value.(string) != "val" {
		t.Error("inserted value has a different value")
	}
	if cache.lruList.Len() != 0 {
		t.Error("Element inserted in wrong list")
	}
	//check that it does not reinitialize when already initialized.
	cache, _ = New(10, "anyContext")
	cache.cache["hello"] = nil
	cache.cacheAnyContext["asdf"] = nil
	list := cache.list
	lruList := cache.lruList
	cache.Add("val", true, ".", "many", "keys")
	if cache.list != list || cache.lruList != lruList || len(cache.cache) != 2 || len(cache.cacheAnyContext) != 2 {
		t.Error("cache reinitialized")
	}
	//check that external element is added correctly
	cache, _ = New(10, "anyContext")
	cache.Add("val", false, ".", "many", "keys")
	if _, ok := cache.cache[".:many:keys"]; !ok {
		t.Error("Value not added to cache")
	}
	if _, ok := cache.cacheAnyContext["many:keys"]; !ok {
		t.Error("Value not added to cacheAnyContext")
	}
	if cache.lruList.Front().Value.(*entry).value.(string) != "val" {
		t.Error("inserted value has a different value")
	}
	if cache.list.Len() != 0 {
		t.Error("Element inserted in wrong list")
	}
	//check that element is only added to cacheAnyContext if hasAnyContext is true
	cache, _ = New(10, "noAnyContext")
	cache.Add("val", false, ".", "many", "keys")
	if _, ok := cache.cache[".:many:keys"]; !ok {
		t.Error("Value not added to cache")
	}
	if _, ok := cache.cacheAnyContext["many:keys"]; ok {
		t.Error("Value must not be added to cacheAnyContext")
	}
	if cache.lruList.Front().Value.(*entry).value.(string) != "val" {
		t.Error("inserted value has a different value")
	}
	if cache.list.Len() != 0 {
		t.Error("Element inserted in wrong list")
	}
	//check that cache size exceeds not maximum
	cache, _ = New(1, "anyContext")
	cache.Add("val", false, ".", "many", "keys")
	cache.Add("val", false, ".", "many", "keys2")
	cache.Add("val", false, ".", "many", "keys3")
	if len(cache.cache) > 1 || len(cache.cacheAnyContext) > 1 || cache.lruList.Len() > 1 {
		t.Errorf("Too many elements in cache. len(cache)=%d, len(cacheAnyContext)=%d, lrulist.Len()=%d",
			len(cache.cache), len(cache.cacheAnyContext), cache.lruList.Len())
	}
	//concurrency test
	runs := 1000
	cache, _ = New(runs, "anyContext")
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go addValue(i, cache, &wg)
	}
	wg.Wait()
	if len(cache.cache) != runs || len(cache.cacheAnyContext) != runs || cache.lruList.Len() != runs {
		t.Errorf("Race condition: some data was not added to the set. len(cache)=%d, len(cacheAnyContext)=%d, lrulist.Len()=%d",
			len(cache.cache), len(cache.cacheAnyContext), cache.lruList.Len())
	}
}

func addValue(i int, cache *Cache, wg *sync.WaitGroup) {
	cache.Add(i, false, ".", "hello", strconv.Itoa(i))
	wg.Done()
}

func TestParseKeys(t *testing.T) {
	inputs := [][]string{
		[]string{"Test"},
		[]string{"a", "b"},
		[]string{"a", "b", "c"},
	}
	want := []string{"Test", "a:b", "a:b:c"}
	for i, input := range inputs {
		if parseKeys(input) != want[i] {
			t.Errorf("Expected value=%s but got=%s on input %v", want[i], parseKeys(input), input)
		}
	}
}

func TestContains(t *testing.T) {
	cache, _ := New(10, "anyContext")
	if cache.Contains("", "v") {
		t.Error("After init cache should be empty")
	}
	cache.cache["con:key"] = nil
	if !cache.Contains("con", "key") {
		t.Error("cache should contain key con:key")
	}
	cache.cacheAnyContext["any"] = nil
	if !cache.Contains("", "any") {
		t.Error("cache should contain key any")
	}
	cache.cache["con:hey:you"] = nil
	if !cache.Contains("con", "hey", "you") {
		t.Error("cache should contain key con:hey:you")
	}
	delete(cache.cache, "con:hey:you")
	if cache.Contains("con", "hey", "you") {
		t.Error("cache should not contain key con:hey:you anymore")
	}

	//concurrency test
	runs := 100000
	cache, _ = New(runs, "anyContext")
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go containsValue(cache, &wg, t)
	}
	wg.Wait()
}

func containsValue(cache *Cache, wg *sync.WaitGroup, t *testing.T) {
	if cache.Contains(".", "hello") {
		t.Error("Does not contain this value")
	}
	wg.Done()
}

func TestGet(t *testing.T) {
	cache, _ := New(10, "anyContext")
	//check return values when element not contained
	if val, ok := cache.Get("", "v"); val != nil || ok {
		t.Error("After init cache should be empty")
	}
	if val, ok := cache.Get("a", "v"); val != nil || ok {
		t.Error("After init cache should be empty")
	}
	//check return values when element is contained in context and non context case
	ele := cache.lruList.PushBack(&entry{value: "value"})
	cache.cache["con:test:my"] = ele
	cache.cacheAnyContext["test:my"] = ele
	val, ok := cache.Get("con", "test", "my")
	if !ok {
		t.Error("After init cache should be empty")
	}
	if val.(string) != "value" {
		t.Error("unexpected value returned")
	}
	val, ok = cache.Get("", "test", "my")
	if !ok {
		t.Error("After init cache should be empty")
	}
	if val.(string) != "value" {
		t.Error("unexpected value returned")
	}
}

func TestKeys(t *testing.T) {
	cache, _ := New(10, "anyContext")
	if len(cache.Keys()) != 0 {
		t.Error("cache not initialized with zero elements")
	}
	ele := &list.Element{Value: &entry{context: "ctx", key: "key1:key3"}}
	cache.cache["key1"] = ele
	if len(cache.Keys()) != 1 {
		t.Errorf("Wrong key count")
	}
	if cache.Keys()[0][0] != "ctx" || cache.Keys()[0][1] != "key1:key3" {
		t.Errorf("Expected key: [ctx,key1:key3], got:%v", cache.Keys()[0])
	}
	//cacheAnyContext should not affect getKeys() result!
	cache.cacheAnyContext["key1"] = ele
	cache.cacheAnyContext["newKey"] = ele
	if len(cache.Keys()) != 1 {
		t.Errorf("Wrong key count")
	}
	if cache.Keys()[0][0] != "ctx" || cache.Keys()[0][1] != "key1:key3" {
		t.Errorf("Expected key: [ctx,key1:key3], got:%v", cache.Keys()[0])
	}
	//add second key
	ele = &list.Element{Value: &entry{context: "ctx", key: "key2:key3"}}
	cache.cache["key2"] = ele
	if len(cache.Keys()) != 2 {
		t.Errorf("Wrong key count")
	}
	//adding same key should not change count.
	cache.cache["key2"] = ele
	if len(cache.Keys()) != 2 {
		t.Errorf("Wrong key count")
	}
}

func TestLen(t *testing.T) {
	cache, _ := New(10, "anyContext")
	if cache.Len() != 0 {
		t.Error("cache not initialized with zero elements")
	}
	el1 := cache.lruList.PushFront("elem")
	if cache.Len() != 1 {
		t.Errorf("incorrect size of cache, expected 1, got:%d", cache.Len())
	}
	el2 := cache.list.PushFront("elem")
	if cache.Len() != 2 {
		t.Errorf("incorrect size of cache, expected 2, got:%d", cache.Len())
	}
	cache.lruList.Remove(el1)
	if cache.Len() != 1 {
		t.Errorf("incorrect size of cache, expected 1, got:%d", cache.Len())
	}
	cache.list.Remove(el2)
	if cache.Len() != 0 {
		t.Errorf("incorrect size of cache, expected 0, got:%d", cache.Len())
	}
}

//TODO CFE test onEvicted function
func TestRemove(t *testing.T) {
	cache, _ := New(10, "anyContext")
	ele := cache.lruList.PushBack(&entry{value: "value", internal: false})
	cache.list.PushBack(&entry{value: "value", internal: true})
	cache.cache["con:test:my"] = ele
	cache.cacheAnyContext["test:my"] = ele
	if cache.Remove("d", "he") {
		t.Error("Deletion of a non existing element should return false")
	}
	//anycontext and external, no effect on internal list
	if !cache.Remove("con", "test", "my") {
		t.Error("Deletion of an existing element should return true")
	}
	if len(cache.cache) > 0 {
		t.Error("cache should contain no elements after deletion")
	}
	if len(cache.cacheAnyContext) > 0 {
		t.Error("cache should contain no elements after deletion")
	}
	if cache.lruList.Len() > 0 {
		t.Error("lrulist should contain no elements after deletion")
	}
	if cache.list.Len() != 1 {
		t.Error("element in external list should not be affected")
	}
	//anycontext and internal, no effect on lru (external) list
	cache, _ = New(10, "anyContext")
	ele = cache.list.PushBack(&entry{value: "value", internal: true})
	cache.lruList.PushBack(&entry{value: "value", internal: false})
	cache.cache["con:test:my"] = ele
	cache.cacheAnyContext["test:my"] = ele
	if !cache.Remove("con", "test", "my") {
		t.Error("Deletion of an existing element should return true")
	}
	if len(cache.cache) > 0 {
		t.Error("cache should contain no elements after deletion")
	}
	if len(cache.cacheAnyContext) > 0 {
		t.Error("cache should contain no elements after deletion")
	}
	if cache.list.Len() > 0 {
		t.Error("lrulist should contain no elements after deletion")
	}
	if cache.lruList.Len() != 1 {
		t.Error("element in external list should not be affected")
	}

	//concurrency test
	runs := 1000
	cache, _ = New(runs, "anyContext")
	for i := 0; i < runs; i++ {
		cache.Add("val", false, ".", "Hello", strconv.Itoa(i))
	}
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go removeValue(i, cache, &wg)
	}
	wg.Wait()
	if len(cache.cache) != 0 || len(cache.cacheAnyContext) != 0 || cache.lruList.Len() != 0 {
		t.Errorf("Race condition: some data was not removed from the set. len(cache)=%d, len(cacheAnyContext)=%d, lrulist.Len()=%d",
			len(cache.cache), len(cache.cacheAnyContext), cache.lruList.Len())
	}
}

func removeValue(i int, cache *Cache, wg *sync.WaitGroup) {
	cache.Remove(".", "Hello", strconv.Itoa(i))
	wg.Done()
}

//TODO CFE test onEvicted function
func TestRemoveWithStrategy(t *testing.T) {
	cache, _ := New(10, "anyContext")
	if cache.RemoveWithStrategy() {
		t.Error("Should return false, as there is nothing to remove")
	}
	ele := cache.list.PushBack(&entry{value: "value", internal: true})
	cache.cache["con:test:my"] = ele
	cache.cacheAnyContext["test:my"] = ele
	//internal list must not be affected by deletion
	if cache.RemoveWithStrategy() {
		t.Error("Should return false, as there is nothing to remove")
	}
	if cache.list.Len() == 0 {
		t.Error("Internal element should not have been removed")
	}
	if len(cache.cache) != 1 {
		t.Error("Internal element should not have been removed")
	}
	if len(cache.cacheAnyContext) != 1 {
		t.Error("Internal element should not have been removed")
	}
	//add external list which are subject to lru removal
	ele = cache.lruList.PushBack(&entry{value: "value", internal: false, context: "con", key: "ext:1"})
	cache.cache["con:ext:1"] = ele
	cache.cacheAnyContext["ext:1"] = ele
	ele2 := cache.lruList.PushBack(&entry{value: "value2", internal: false, context: "con", key: "ext:2"})
	cache.cache["con:ext:2"] = ele2
	cache.cacheAnyContext["ext:2"] = ele2
	if !cache.RemoveWithStrategy() {
		t.Error("Should return true, as there is something to remove")
	}
	if cache.list.Len() == 0 {
		t.Error("Internal element should not have been removed")
	}
	if len(cache.cache) != 2 {
		t.Errorf("There should be 2 elements in the cache, found %d, cache: %v", len(cache.cache), cache.cache)
	}
	if len(cache.cacheAnyContext) != 2 {
		t.Errorf("There should be 2 elements in the cache, found %d, cache: %v", len(cache.cacheAnyContext), cache.cacheAnyContext)
	}
	if cache.lruList.Len() != 1 {
		t.Error("lru (external) list has wrong number of element")
	}
	//check if last element was removed
	if cache.lruList.Front().Value.(*entry).value.(string) != "value" {
		t.Error("Wrong element deleted")
	}

	//concurrency test
	runs := 1000
	cache, _ = New(runs, "anyContext")
	for i := 0; i < runs; i++ {
		cache.Add("val", false, ".", "Hello", strconv.Itoa(i))
	}
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go removeWithStrategyValue(cache, &wg)
	}
	wg.Wait()
	if len(cache.cache) != 0 || len(cache.cacheAnyContext) != 0 || cache.lruList.Len() != 0 {
		t.Errorf("Race condition: some data was not removed from the set. len(cache)=%d, len(cacheAnyContext)=%d, lrulist.Len()=%d",
			len(cache.cache), len(cache.cacheAnyContext), cache.lruList.Len())
	}
}

func removeWithStrategyValue(cache *Cache, wg *sync.WaitGroup) {
	cache.RemoveWithStrategy()
	wg.Done()
}

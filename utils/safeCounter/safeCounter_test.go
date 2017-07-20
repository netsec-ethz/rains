package safeCounter

import (
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	counter := New(5)
	counter2 := New(5)
	if counter == counter2 {
		t.Errorf("New did not create a new instance, %v == %v", counter, counter2)
	}
	if counter.count != 0 || counter.maxCount != 5 {
		t.Errorf("counter values are not correctly initialized. expected=0/5 actual=%s", counter)
	}
}

func TestInc(t *testing.T) {
	counter := New(2)
	ok := counter.Inc()
	if ok || counter.count != 1 {
		t.Errorf("counter value after increment wrong. %v", counter)
	}
	ok = counter.Inc()
	if !ok || counter.count != 2 {
		t.Errorf("counter value after increment wrong. %v", counter)
	}
	//"concurrency test"
	runs := 100000
	counter = New(runs)
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go inc(counter, &wg)
	}
	wg.Wait()
	if counter.count != runs {
		t.Errorf("Race condition: some data was not added to the counter. expected=%d actual=%d", runs, counter)
	}
}

func inc(counter *Counter, wg *sync.WaitGroup) {
	counter.Inc()
	wg.Done()
}

func TestAdd(t *testing.T) {
	counter := New(5)
	ok := counter.Add(2)
	if ok || counter.count != 2 {
		t.Errorf("counter value after adding wrong. %v", counter)
	}
	ok = counter.Add(3)
	if !ok || counter.count != 5 {
		t.Errorf("counter value after adding wrong. %v", counter)
	}
	//"concurrency test"
	runs := 100000
	counter = New(runs)
	var wg sync.WaitGroup
	for i := 0; i < runs/2; i++ {
		wg.Add(1)
		go add(counter, &wg)
	}
	wg.Wait()
	if counter.count != runs {
		t.Errorf("Race condition: some data was not added to the counter. expected=%d actual=%d", runs, counter)
	}
}

func add(counter *Counter, wg *sync.WaitGroup) {
	counter.Add(2)
	wg.Done()
}

func TestDec(t *testing.T) {
	counter := New(2)
	counter.count = 2
	counter.Dec()
	if counter.count != 1 {
		t.Errorf("counter value after decrementing wrong. %v", counter)
	}
	//"concurrency test"
	runs := 100000
	counter = New(runs)
	counter.count = runs
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go dec(counter, &wg)
	}
	wg.Wait()
	if counter.count != 0 {
		t.Errorf("Race condition: some data was not added to the counter. expected=%d actual=%d", 0, counter)
	}
}

func dec(counter *Counter, wg *sync.WaitGroup) {
	counter.Dec()
	wg.Done()
}

func TestSub(t *testing.T) {
	counter := New(5)
	counter.count = 5
	counter.Sub(2)
	if counter.count != 3 {
		t.Errorf("counter value after subtracting wrong. %v", counter)
	}
	counter.Sub(3)
	if counter.count != 0 {
		t.Errorf("counter value after subtracting wrong. %v", counter)
	}
	//"concurrency test"
	runs := 100000
	counter = New(runs)
	counter.count = runs
	var wg sync.WaitGroup
	for i := 0; i < runs/2; i++ {
		wg.Add(1)
		go sub(counter, &wg)
	}
	wg.Wait()
	if counter.count != 0 {
		t.Errorf("Race condition: some data was not added to the counter. expected=%d actual=%d", 0, counter)
	}
}

func sub(counter *Counter, wg *sync.WaitGroup) {
	counter.Sub(2)
	wg.Done()
}

func TestValue(t *testing.T) {
	counter := New(5)
	counter.count = 3
	if count, maxCount := counter.Value(); count != 3 || maxCount != 5 {
		t.Errorf("response of the counter's value wrong. %v", counter)
	}
	counter.count = 6
	if count, maxCount := counter.Value(); count != 6 || maxCount != 5 {
		t.Errorf("response of the counter's value wrong. %v", counter)
	}
}

func TestIsFull(t *testing.T) {
	counter := New(5)
	counter.count = 3
	if counter.isFull() {
		t.Errorf("counter is not full. %v", counter)
	}
	counter.count = 6
	if !counter.isFull() {
		t.Errorf("counter is full. %v", counter)
	}
}

func TestString(t *testing.T) {
	counter := New(5)
	if counter.String() != "0/5" {
		t.Errorf("string representation of the counter wrong.")
	}
	counter.count = 3
	if counter.String() != "3/5" {
		t.Errorf("string representation of the counter wrong.")
	}
}

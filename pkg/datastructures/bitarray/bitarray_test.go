package bitarray

import "testing"

func TestSetBit(t *testing.T) {
	b := make(BitArray, 2)
	if b.SetBit(16) == nil {
		t.Errorf("SetBit did not return an error")
	}
	b.SetBit(0)
	if b[0] != 1 {
		t.Errorf("SetBit did not set bit at position 0 in first block, value=%d", b[0])
	}
	b.SetBit(0)
	if b[0] != 1 {
		t.Errorf("Setting same bit twice reverted the outcome, value=%d", b[0])
	}
	b.SetBit(1)
	if b[0] != 3 {
		t.Errorf("SetBit did not set bit at position 1 in first block, value=%d", b[0])
	}
	b.SetBit(8)
	if b[1] != 1 {
		t.Errorf("SetBit did not set bit at position 0 in second block, value=%d", b[1])
	}

}

func TestGetBit(t *testing.T) {
	b := make(BitArray, 2)
	b[0] = 3
	if _, err := b.GetBit(16); err == nil {
		t.Errorf("GetBit did not return an error")
	}
	if val, err := b.GetBit(0); err != nil || !val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(1); err != nil || !val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(2); err != nil || val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(3); err != nil || val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(4); err != nil || val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(5); err != nil || val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(6); err != nil || val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(7); err != nil || val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	b[1] = 1
	if val, err := b.GetBit(8); err != nil || !val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}
	if val, err := b.GetBit(9); err != nil || val {
		t.Errorf("GetBit returned wrong value, value=%v", val)
	}

}

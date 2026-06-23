package detector

import "testing"

func TestHeavyKeeper_EstimateDecayPrune(t *testing.T) {
	hk := newHeavyKeeper(1024, 4, heavyKeeperDecay)
	hk.add(0xAAAA, 1000)
	hk.add(0xAAAA, 1000) // heavy: ~2000
	hk.add(0xBBBB, 10)   // light

	if e := hk.estimate(0xAAAA); e < 1500 {
		t.Fatalf("heavy estimate = %f, want ~2000", e)
	}
	if e := hk.estimate(0xBBBB); e < 5 || e > 50 {
		t.Fatalf("light estimate = %f, want ~10", e)
	}
	if e := hk.estimate(0xCCCC); e != 0 {
		t.Fatalf("absent estimate = %f, want 0", e)
	}

	// Four halvings: light 10 -> 0.625 (< pruneBelow, freed); heavy 2000 -> 125.
	for i := 0; i < 4; i++ {
		hk.decayAll(0.5)
	}
	if e := hk.estimate(0xBBBB); e != 0 {
		t.Fatalf("light not pruned after decay: %f", e)
	}
	if e := hk.estimate(0xAAAA); e < 100 {
		t.Fatalf("heavy decayed too far: %f", e)
	}
}

// The heavy hitter must outscore every light flow despite many of them.
func TestHeavyKeeper_HeavyHitterStandsOut(t *testing.T) {
	hk := newHeavyKeeper(2048, 4, heavyKeeperDecay)
	light := make([]uint64, 500)
	for i := range light {
		light[i] = uint64(i)*0x100 + 1
		hk.add(light[i], 5)
	}
	const heavy = uint64(0xDEADBEEF)
	for i := 0; i < 200; i++ {
		hk.add(heavy, 100)
	}

	he := hk.estimate(heavy)
	if he < 10000 {
		t.Fatalf("heavy estimate = %f, want >> light", he)
	}
	for _, k := range light {
		if le := hk.estimate(k); le > he {
			t.Fatalf("light estimate %f exceeded heavy %f", le, he)
		}
	}
}

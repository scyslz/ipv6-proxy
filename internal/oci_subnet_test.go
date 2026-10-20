package internal

import (
	"net"
	"testing"
)

func TestAllocateIPv6Subnet(t *testing.T) {
	vcn := &OciVcn{IPv6CidrBlocks: []string{"2603:c024:4517:a800::/56"}}
	subnets := []OciSubnet{
		{IPv6CidrBlocks: []string{"2603:c024:4517:a800::/64"}},
		{IPv6CidrBlocks: []string{"2603:c024:4517:a8ff::/64"}},
	}
	got, err := allocateIPv6Subnet(vcn, subnets)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2603:c024:4517:a801::/64" {
		t.Fatalf("got %s, want 2603:c024:4517:a801::/64", got)
	}
}

func TestAllocateIPv6SubnetExhausted(t *testing.T) {
	vcn := &OciVcn{IPv6CidrBlocks: []string{"2603:c024:4517:a8ff::/64"}}
	subnets := []OciSubnet{{IPv6CidrBlocks: []string{"2603:c024:4517:a8ff::/64"}}}
	if _, err := allocateIPv6Subnet(vcn, subnets); err == nil {
		t.Fatal("expected exhaustion error")
	}
}

func TestAllocateIPv4Subnet(t *testing.T) {
	vcn := &OciVcn{CidrBlocks: []string{"10.0.0.0/16"}}
	subnets := []OciSubnet{{CidrBlock: "10.0.0.0/24"}, {CidrBlock: "10.0.1.0/24"}}
	got, err := allocateIPv4Subnet(vcn, subnets)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.2.0/24" {
		t.Fatalf("got %s, want 10.0.2.0/24", got)
	}
}

func TestPrefix64Of(t *testing.T) {
	cases := map[string]string{
		"2603:c024:4517:a81e:7d21:1a63:5b61:1":     "2603:c024:4517:a81e::/64",
		"2603:c024:4517:a81e:7d21:1a63:5b61:0/112": "2603:c024:4517:a81e::/64",
		"2603:c024:4517:a81e::/64":                 "2603:c024:4517:a81e::/64",
		"10.0.0.1":                                 "",
		"":                                         "",
	}
	for in, want := range cases {
		if got := prefix64Of(in); got != want {
			t.Errorf("prefix64Of(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSubnetCandidate(t *testing.T) {
	_, parent, err := net.ParseCIDR("2603:c024:4517:a800::/56")
	if err != nil {
		t.Fatal(err)
	}
	ip := subnetCandidate(parent, 0x1f, 64)
	if ip.String() != "2603:c024:4517:a81f::" {
		t.Fatalf("got %s", ip)
	}
}

func TestSelectVnicPrefix(t *testing.T) {
	l112, l80 := 112, 80
	list := []OciIpv6{
		{ID: "used", IPAddress: "2603:c024:4517:a801::", CidrPrefixLength: &l112, LifecycleState: "PROVISIONING"},
		{ID: "other-subnet", IPAddress: "2603:c024:4517:a900::", CidrPrefixLength: &l112, LifecycleState: "AVAILABLE"},
		{ID: "wide", IPAddress: "2603:c024:4517:a800::", CidrPrefixLength: &l80, LifecycleState: "AVAILABLE"},
		{ID: "best", IPAddress: "2603:c024:4517:a800::2", CidrPrefixLength: &l112, LifecycleState: "AVAILABLE"},
	}
	subnet := "2603:c024:4517:a800::/64"
	if got := selectVnicPrefix(list, subnet, 0, 112); got == nil || got.ID != "best" {
		t.Fatalf("preferLen selection = %+v, want best", got)
	}
	if got := selectVnicPrefix(list, subnet, 80, 112); got == nil || got.ID != "wide" {
		t.Fatalf("desiredLen selection = %+v, want wide", got)
	}
	if got := selectVnicPrefix(list, "2603:c024:4517:aa00::/64", 0, 112); got != nil {
		t.Fatalf("expected no prefix in unrelated subnet, got %+v", got)
	}
}

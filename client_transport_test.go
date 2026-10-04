package vpn

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestTransientLinkWriteError(t *testing.T) {
	for _, err := range []error{
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		syscall.ENETDOWN,
		syscall.EADDRNOTAVAIL,
		fmt.Errorf("wrapped transport error: %w", syscall.ENETUNREACH),
	} {
		if !isTransientLinkWriteError(err) {
			t.Errorf("isTransientLinkWriteError(%v) = false, want true", err)
		}
	}
}

func TestPermanentLinkWriteError(t *testing.T) {
	for _, err := range []error{
		syscall.EPIPE,
		syscall.ECONNRESET,
		errors.New("unclassified write failure"),
	} {
		if isTransientLinkWriteError(err) {
			t.Errorf("isTransientLinkWriteError(%v) = true, want false", err)
		}
	}
}

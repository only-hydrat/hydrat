//go:build unix

package onion

import (
	"errors"
	"os"
	"syscall"
)

func openBookLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
}
func lockBook(lock *os.File) error {
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("onion address book already owned")
	}
	return nil
}

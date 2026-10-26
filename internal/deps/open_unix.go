//go:build unix

package deps

import (
	"os"
	"syscall"
)

func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	return checkRegular(f)
}

//go:build !unix

package deps

import "os"

func openRegular(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return checkRegular(f)
}

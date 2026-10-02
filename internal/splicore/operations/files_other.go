//go:build !linux

package operations

import (
	"fmt"
	"os"
)

func PrivateDirectory(string) error { return fmt.Errorf("production service operations require Linux") }

func recordLock(string) (*os.File, error) { return nil, fmt.Errorf("service records require Linux") }

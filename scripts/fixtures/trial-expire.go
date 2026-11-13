// Test-only database fixture. This file is copied only by trial-expire.Dockerfile.
package main

import (
	"authgo/internal/db"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	id, e := strconv.ParseUint(os.Args[1], 10, 64)
	if e != nil || id == 0 {
		os.Exit(2)
	}
	d, e := db.Open("/data", 5*time.Second)
	if e != nil {
		os.Exit(1)
	}
	result := d.Exec("UPDATE licenses SET expires_at=? WHERE id=? AND type='trial'", time.Now().UTC().Add(-time.Second), id)
	if result.Error != nil || result.RowsAffected != 1 {
		os.Exit(1)
	}
}

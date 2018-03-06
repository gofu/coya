package coya

import (
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const (
	Base16 RandSet = "abcdefg0123456789"
	Base62 RandSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type RandSet string

func (set RandSet) Generate(n int) string {
	b := make([]uint8, n)
	l := len(set)
	for i := range b {
		b[i] = set[rand.Intn(l)]
	}
	return string(b)
}

type UUID []byte

func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", string(u[:4]), string(u[4:6]), string(u[6:8]), string(u[8:10]), string(u[10:]))
}

func UUID4() UUID {
	uuid := make(UUID, 16)
	for i := 0; i < 16; i++ {
		uuid[i] = byte(rand.Intn(256))
		if i == 6 {
			uuid[i] = (uuid[i] & 0x0f) | (4 << 4)
		} else if i == 8 {
			uuid[8] = (uuid[8] & 0xbf) | 0x80
		}
	}
	return uuid
}

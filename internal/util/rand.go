package util

import (
	"database/sql"
	"fmt"
	"math/rand"
	"time"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz"

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RandomInt(min, max int64) int64 {
	return min + rand.Int63n(max-min+1)
}

func RandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func RandomName() string {
	return RandomString(6)
}

func RandomEmail() string {
	return fmt.Sprintf("%s@email.com", RandomString(6))
}

func RandomSqlNullTime() sql.NullTime {
	return sql.NullTime{
		Time:  time.Now().Add(time.Duration(RandomInt(-720, 720)) * time.Hour),
		Valid: rand.Intn(2) == 1, // Randomly make it valid or invalid
	}
}

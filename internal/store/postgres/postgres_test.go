package postgres

// These tests need a PostgreSQL server: set KYGATE_TEST_POSTGRES_URL to a
// database KyGate may fill and empty, for example
//
//	docker run -d --name kygate-pg -e POSTGRES_PASSWORD=test -p 55432:5432 pgvector/pgvector:pg17
//	KYGATE_TEST_POSTGRES_URL=postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable go test ./internal/store/postgres/
//
// Without it they are skipped.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/storetest"
)

// freshDB creates an empty database on the server for one test.
func freshDB(t *testing.T) string {
	base := os.Getenv("KYGATE_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("KYGATE_TEST_POSTGRES_URL is not set")
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := fmt.Sprintf("kygate_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a, _ := sql.Open("pgx", base)
		defer a.Close()
		a.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})
	i := strings.LastIndex(base, "/")
	q := ""
	if j := strings.Index(base[i:], "?"); j >= 0 {
		q = base[i+j:]
	}
	return base[:i+1] + name + q
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Database {
		db, err := Open(freshDB(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	})
}

// Several processes starting together migrate once.
func TestConcurrentMigrations(t *testing.T) {
	url := freshDB(t)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := Open(url)
			if err != nil {
				errs <- err
				return
			}
			db.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestSemanticStore(t *testing.T) {
	db, err := Open(freshDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now()
	for i, exp := range []time.Duration{time.Hour, time.Hour, -time.Minute} {
		db.PutSemantic(ctx, store.SemanticRecord{Key: fmt.Sprint("k", i), Context: "c1", OrgID: "o", Sealed: []byte{byte(i), 0}, Expires: now.Add(exp)})
		time.Sleep(2 * time.Millisecond)
	}
	got, err := db.ListSemantic(ctx, "o", "c1", now, 10)
	if err != nil || len(got) != 2 || got[0].Key != "k1" {
		t.Fatalf("unexpired, newest first: %v %+v", err, got)
	}
	if n, err := db.TrimSemantic(ctx, now, 1); err != nil || n != 2 {
		t.Fatalf("the expired one, then the oldest beyond 1: %d %v", n, err)
	}
	if s, _ := db.SemanticStats(ctx); s.Entries != 1 || s.Bytes != 2 {
		t.Fatalf("%+v", s)
	}
	// Purges by label (GV-4).
	db.PutSemantic(ctx, store.SemanticRecord{Key: "t1", Context: "c9", OrgID: "o", Sealed: []byte{1}, Expires: now.Add(time.Hour), Labels: []string{"aa", "bb"}})
	db.PutSemantic(ctx, store.SemanticRecord{Key: "t2", Context: "c9", OrgID: "o", Sealed: []byte{1}, Expires: now.Add(time.Hour), Labels: []string{"aab"}})
	if n, err := db.PurgeSemantic(ctx, "aa"); err != nil || n != 1 {
		t.Fatalf("a label matches whole: %d %v", n, err)
	}
	if n, _ := db.PurgeSemantic(ctx, ""); n != 2 {
		t.Fatalf("purge all: %d", n)
	}
}

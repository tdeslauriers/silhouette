package crypt

import (
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// testing to validate that price of concurrency does not exceed the cost of
// sequential encryption and decryption for address records
// Note: this is a benchmark test, not a unit test, and is intended to be run with the -bench flag

// setupCryptor creates a cryptor for testing
func setupCryptor() data.Cryptor {
	// Use a fixed key for consistent benchmarking
	key := []byte("12345678901234567890123456789012") // 32 bytes for AES-256
	return data.NewServiceAesGcmKey(key)
}

// createSampleAddress creates a sample address with Star Wars themed fields
func createSampleAddress() *sqlc.Address {
	return &sqlc.Address{
		Uuid:         "darth-vader-uuid",
		Slug:         "death-star-base",
		AddressLine1: sql.NullString{String: "Death Star Control Room", Valid: true},
		AddressLine2: sql.NullString{String: "Sector 7G", Valid: true},
		City:         sql.NullString{String: "Coruscant", Valid: true},
		State:        sql.NullString{String: "Galactic Empire", Valid: true},
		Zip:          sql.NullString{String: "DS-001", Valid: true},
		Country:      sql.NullString{String: "Outer Rim Territories", Valid: true},
		IsCurrent:    true,
		IsPrimary:    true,
		UpdatedAt:    time.Now(),
		CreatedAt:    time.Now(),
	}
}

// BenchmarkEncryptAddressConcurrent benchmarks the concurrent encryption
func BenchmarkEncryptAddressConcurrent(b *testing.B) {
	cryptor := setupCryptor()
	c := NewAddressCryptor(cryptor)
	addr := createSampleAddress()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clone the address to avoid modifying the original
		testAddr := *addr
		err := c.EncryptAddress(&testAddr)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptAddressSequential benchmarks sequential encryption
func BenchmarkEncryptAddressSequential(b *testing.B) {
	cryptor := setupCryptor()
	addr := createSampleAddress()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clone the address
		testAddr := *addr

		// Encrypt slug
		if testAddr.Slug != "" {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.EncryptField("slug", testAddr.Slug, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.Slug = <-resultCh
		}

		// Encrypt address_line_1
		if testAddr.AddressLine1.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.EncryptField("address_line_1", testAddr.AddressLine1.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.AddressLine1 = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Encrypt address_line_2
		if testAddr.AddressLine2.Valid && len(testAddr.AddressLine2.String) > 0 {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.EncryptField("address_line_2", testAddr.AddressLine2.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.AddressLine2 = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Encrypt city
		if testAddr.City.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.EncryptField("city", testAddr.City.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.City = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Encrypt state
		if testAddr.State.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.EncryptField("state", testAddr.State.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.State = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Encrypt zip
		if testAddr.Zip.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.EncryptField("zip", testAddr.Zip.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.Zip = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Encrypt country
		if testAddr.Country.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.EncryptField("country", testAddr.Country.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.Country = sql.NullString{String: <-resultCh, Valid: true}
		}
	}
}

// BenchmarkDecryptAddressConcurrent benchmarks the concurrent decryption
func BenchmarkDecryptAddressConcurrent(b *testing.B) {
	cryptor := setupCryptor()
	c := NewAddressCryptor(cryptor)
	addr := createSampleAddress()

	// Pre-encrypt the address
	err := c.EncryptAddress(addr)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clone the encrypted address
		testAddr := *addr
		err := c.DecryptAddress(&testAddr)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptAddressSequential benchmarks sequential decryption
func BenchmarkDecryptAddressSequential(b *testing.B) {
	cryptor := setupCryptor()
	addr := createSampleAddress()

	// Pre-encrypt the address sequentially
	if addr.Slug != "" {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		wg := sync.WaitGroup{}
		wg.Add(1)
		cryptor.EncryptField("slug", addr.Slug, resultCh, errCh, &wg)
		wg.Wait()
		close(resultCh)
		close(errCh)
		if len(errCh) > 0 {
			err := <-errCh
			b.Fatal(err)
		}
		addr.Slug = <-resultCh
	}
	if addr.AddressLine1.Valid {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		wg := sync.WaitGroup{}
		wg.Add(1)
		cryptor.EncryptField("address_line_1", addr.AddressLine1.String, resultCh, errCh, &wg)
		wg.Wait()
		close(resultCh)
		close(errCh)
		if len(errCh) > 0 {
			err := <-errCh
			b.Fatal(err)
		}
		addr.AddressLine1 = sql.NullString{String: <-resultCh, Valid: true}
	}
	if addr.AddressLine2.Valid && len(addr.AddressLine2.String) > 0 {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		wg := sync.WaitGroup{}
		wg.Add(1)
		cryptor.EncryptField("address_line_2", addr.AddressLine2.String, resultCh, errCh, &wg)
		wg.Wait()
		close(resultCh)
		close(errCh)
		if len(errCh) > 0 {
			err := <-errCh
			b.Fatal(err)
		}
		addr.AddressLine2 = sql.NullString{String: <-resultCh, Valid: true}
	}
	if addr.City.Valid {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		wg := sync.WaitGroup{}
		wg.Add(1)
		cryptor.EncryptField("city", addr.City.String, resultCh, errCh, &wg)
		wg.Wait()
		close(resultCh)
		close(errCh)
		if len(errCh) > 0 {
			err := <-errCh
			b.Fatal(err)
		}
		addr.City = sql.NullString{String: <-resultCh, Valid: true}
	}
	if addr.State.Valid {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		wg := sync.WaitGroup{}
		wg.Add(1)
		cryptor.EncryptField("state", addr.State.String, resultCh, errCh, &wg)
		wg.Wait()
		close(resultCh)
		close(errCh)
		if len(errCh) > 0 {
			err := <-errCh
			b.Fatal(err)
		}
		addr.State = sql.NullString{String: <-resultCh, Valid: true}
	}
	if addr.Zip.Valid {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		wg := sync.WaitGroup{}
		wg.Add(1)
		cryptor.EncryptField("zip", addr.Zip.String, resultCh, errCh, &wg)
		wg.Wait()
		close(resultCh)
		close(errCh)
		if len(errCh) > 0 {
			err := <-errCh
			b.Fatal(err)
		}
		addr.Zip = sql.NullString{String: <-resultCh, Valid: true}
	}
	if addr.Country.Valid {
		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)
		wg := sync.WaitGroup{}
		wg.Add(1)
		cryptor.EncryptField("country", addr.Country.String, resultCh, errCh, &wg)
		wg.Wait()
		close(resultCh)
		close(errCh)
		if len(errCh) > 0 {
			err := <-errCh
			b.Fatal(err)
		}
		addr.Country = sql.NullString{String: <-resultCh, Valid: true}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clone the encrypted address
		testAddr := *addr

		// Decrypt slug
		if testAddr.Slug != "" {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.DecryptField("slug", testAddr.Slug, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.Slug = <-resultCh
		}

		// Decrypt address_line_1
		if testAddr.AddressLine1.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.DecryptField("address_line_1", testAddr.AddressLine1.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.AddressLine1 = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Decrypt address_line_2
		if testAddr.AddressLine2.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.DecryptField("address line 2", testAddr.AddressLine2.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.AddressLine2 = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Decrypt city
		if testAddr.City.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.DecryptField("city", testAddr.City.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.City = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Decrypt state
		if testAddr.State.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.DecryptField("state", testAddr.State.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.State = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Decrypt zip
		if testAddr.Zip.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.DecryptField("zip", testAddr.Zip.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.Zip = sql.NullString{String: <-resultCh, Valid: true}
		}

		// Decrypt country
		if testAddr.Country.Valid {
			resultCh := make(chan string, 1)
			errCh := make(chan error, 1)
			wg := sync.WaitGroup{}
			wg.Add(1)
			cryptor.DecryptField("country", testAddr.Country.String, resultCh, errCh, &wg)
			wg.Wait()
			close(resultCh)
			close(errCh)
			if len(errCh) > 0 {
				err := <-errCh
				b.Fatal(err)
			}
			testAddr.Country = sql.NullString{String: <-resultCh, Valid: true}
		}
	}
}

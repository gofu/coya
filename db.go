package coya

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"math"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrNotFound = errors.New("entity not found")

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Image struct {
	Name   string `json:"name"`
	Height int    `json:"height"`
	Width  int    `json:"width"`
	Mime   string `json:"mime"`
}

type Portfolio struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Images     []*Image  `json:"images"`
	Categories []string  `json:"categories"`
	Priority   int64     `json:"priority"`
	Chosen     bool      `json:"chosen"`
	CreatedAt  time.Time `json:"-"`
}

func (p *Portfolio) Image() string {
	if len(p.Images) == 0 {
		return ""
	}
	return p.Images[0].Name
}

type BlacklistJWT struct {
	ID    string    `json:"id"`
	Until time.Time `json:"until"`
}

type DB struct {
	Secret       []byte          `json:"secret"`
	Users        []*User         `json:"users"`
	Portfolio    []*Portfolio    `json:"portfolio"`
	Categories   []string        `json:"categories"`
	BlacklistJWT []*BlacklistJWT `json:"blacklist"`
}

type Repo struct {
	file string
	mu   sync.RWMutex
	o    sync.Once
	err  error
	db   *DB
}

func NewRepo(dbPath string) (*Repo, error) {
	repo := &Repo{file: dbPath}
	go repo.cron()
	return repo, repo.ReadDB()
}

var (
	defaultEmail    = "admin@example.com"
	defaultPassword = "admin"
)

func (r *Repo) cron() {
	for {
		time.Sleep(1 * time.Minute)
		_ = r.timeoutJWT()
	}
}

func (r *Repo) timeoutJWT() error {
	r.mu.RLock()
	dirty := false
rewind:
	for i, data := range r.db.BlacklistJWT {
		if data.Until.Before(time.Now()) {
			r.db.BlacklistJWT = append(r.db.BlacklistJWT[:i], r.db.BlacklistJWT[i+1:]...)
			dirty = true
			// Handle reindexing.
			goto rewind
		}
	}
	r.mu.RUnlock()
	if !dirty {
		return nil
	}
	return r.WriteDB()
}

func (r *Repo) Users() []*User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db.Users
}

func (r *Repo) Portfolio() []*Portfolio {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db.Portfolio
}

func (r *Repo) ReadDB() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	read := func() error {
		seeded := false
	again:
		r.db = &DB{Users: []*User{}, Portfolio: []*Portfolio{}, Categories: []string{}, BlacklistJWT: []*BlacklistJWT{}}
		file, err := os.OpenFile(r.file, os.O_RDONLY, 0666)
		if os.IsNotExist(err) && !seeded {
			password, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			r.db.Secret = make([]byte, 16)
			r.db.Users = append(r.db.Users, &User{ID: UUID4().String(), Email: defaultEmail, Password: string(password)})
			if _, err := rand.Read(r.db.Secret); err != nil {
				return err
			}
			data, err := json.Marshal(r.db)
			if err != nil {
				return err
			}
			if err = ioutil.WriteFile(r.file, data, 0666); err != nil {
				return err
			}
			log.Printf("Seeded database %s", r.file)
			seeded = true
			goto again
		}
		if err != nil {
			return err
		}
		defer file.Close()
		return json.NewDecoder(file).Decode(r.db)
	}
	var attempt float64
again:
	err := read()
	if err != nil && attempt < 5 {
		attempt++
		time.Sleep(time.Millisecond * 100 * time.Duration(math.Pow(attempt, 2)))
		goto again
	}
	return err
}

func (r *Repo) WriteDB() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	write := func() error {
		file, err := os.OpenFile(r.file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(file)
		enc.SetIndent("", "\t")
		if err = enc.Encode(r.db); err != nil {
			file.Close()
			return err
		}
		return file.Close()
	}
	var attempt float64
again:
	err := write()
	if err != nil && attempt < 4 {
		attempt++
		time.Sleep(time.Millisecond * 100 * time.Duration(math.Pow(attempt, 2)))
		goto again
	}
	return err
}

func (r *Repo) Secret() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db.Secret
}

func (r *Repo) GetUserByID(id string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.db.Users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, ErrNotFound
}

func (r *Repo) GetUserByEmail(email string) (*User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.db.Users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, ErrNotFound
}

func (r *Repo) IsJWTBlacklisted(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, data := range r.db.BlacklistJWT {
		if data.ID == id {
			return true
		}
	}
	return false
}

func (r *Repo) BlacklistJWT(id string, until time.Time) error {
	r.mu.Lock()
	r.db.BlacklistJWT = append(r.db.BlacklistJWT, &BlacklistJWT{ID: id, Until: until})
	r.mu.Unlock()
	return r.WriteDB()
}

func (r *Repo) AddPortfolio(p *Portfolio) error {
	r.mu.Lock()
	r.db.Portfolio = append(r.db.Portfolio, p)
	r.mu.Unlock()
	return r.WriteDB()
}

func (r *Repo) GetPortfolio(id string) (*Portfolio, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.db.Portfolio {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, ErrNotFound
}

func (r *Repo) GetAndLockPortfolio(id string) (*Portfolio, error) {
	r.mu.Lock()
	for _, p := range r.db.Portfolio {
		if p.ID == id {
			return p, nil
		}
	}
	r.mu.Unlock()
	return nil, ErrNotFound
}

func (r *Repo) Commit() error {
	r.mu.Unlock()
	return r.WriteDB()
}

func (r *Repo) DeletePortfolio(id string) error {
	r.mu.Lock()
	removed := false
	for i, p := range r.db.Portfolio {
		if p.ID == id {
			r.db.Portfolio = append(r.db.Portfolio[:i], r.db.Portfolio[i+1:]...)
			removed = true
			break
		}
	}
	r.mu.Unlock()
	if !removed {
		return nil
	}
	return r.WriteDB()
}

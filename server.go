package coya

//go:generate uglifyjs -o static/script.js ui/script.js
//go:generate cleancss -o static/base.css ui/base.css
//go:generate cleancss -o static/style.css ui/style.css
//go:generate go-bindata -pkg coya static tpl

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"reflect"

	"os/exec"

	"net/mail"

	"net"

	"io/ioutil"

	"os"
	"path"

	"image/jpeg"
	"image/png"

	"math"

	"image"
	"image/color"

	"sort"

	"github.com/gofu/coya/jwt"
	"github.com/nfnt/resize"
	"github.com/oliamb/cutter"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// Used by go-bindata.
const rootDir = ""

var (
	ErrAPIBadRequest   = &res{Error: "Bad request."}
	ErrAPINotFound     = &res{Error: "Not found."}
	ErrAPIDiskWrite    = &res{Error: "Could not write to disk."}
	ErrAPINoSession    = &res{Error: "No session."}
	ErrAPIEmailInvalid = &res{Error: "Invalid email provided."}
	APIOK              = &res{OK: true}
)

type Session struct {
	// JWT data.
	ID       string `json:"jti,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	UserID   string `json:"sub,omitempty"`

	// Custom data.
	RefreshedAt int64  `json:"act,omitempty"`
	Hash        string `json:"hsh,omitempty"`
	User        *User  `json:"-"`
}

func (s *Session) ActiveAt() time.Time {
	if s.RefreshedAt != 0 {
		return time.Unix(s.RefreshedAt, 0)
	}
	return time.Unix(s.IssuedAt, 0)
}

type FileHandler struct {
	Dir string
}

func (h *FileHandler) Save(name string, content []byte, perm os.FileMode) error {
	return ioutil.WriteFile(path.Join(h.Dir, name), content, perm)
}

func (h *FileHandler) Remove(name string) error {
	var attempt float64
again:
	err := os.Remove(path.Join(h.Dir, name))
	if err != nil && !os.IsNotExist(err) && attempt < 4 {
		attempt++
		time.Sleep(time.Millisecond * 100 * time.Duration(math.Pow(attempt, 2)))
		goto again
	}
	return err
}

type Center struct {
	image.Image
	image.Rectangle
}

func (img Center) ColorModel() color.Model {
	return img.Image.ColorModel()
}

func (img Center) Bounds() image.Rectangle {
	return img.Rectangle
}

func (img Center) At(x, y int) color.Color {
	offsetX := (img.Rectangle.Dx() - img.Image.Bounds().Dx()) / 2
	offsetY := (img.Rectangle.Dy() - img.Image.Bounds().Dy()) / 2

	return img.Image.At(x-offsetX, y-offsetY)
}

func (h *FileHandler) SaveStyle(src, dst string, height, width int) error {
	srcFile, err := os.OpenFile(path.Join(h.Dir, src), os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	var encode func(w io.Writer, m image.Image) error
	ext := path.Ext(src)
	switch ext {
	case ".jpg":
		encode = func(w io.Writer, m image.Image) error {
			return jpeg.Encode(w, m, &jpeg.Options{Quality: 89})
		}
	case ".png":
		encode = func(w io.Writer, m image.Image) error {
			return png.Encode(w, m)
		}
	default:
		return fmt.Errorf("unsupported image extension: %s", ext)
	}
	if err != nil {
		return err
	}
	img, _, err := image.Decode(srcFile)
	srcFile.Close()
	if err != nil {
		return fmt.Errorf("decode src image: %s", err)
	}
	img = resize.Thumbnail(uint(width), uint(height), img, resize.Bilinear)
	if height > img.Bounds().Max.Y {
		height = img.Bounds().Max.Y
	}
	if width > img.Bounds().Max.X {
		width = img.Bounds().Max.X
	}
	if height < width {
		width = height
	} else {
		height = width
	}
	img, err = cutter.Crop(img, cutter.Config{Width: width, Height: height, Mode: cutter.Centered})
	if err != nil {
		return fmt.Errorf("crop src image: %s", err)
	}
	if err = os.MkdirAll(path.Dir(path.Join(h.Dir, dst)), 0755); err != nil {
		return fmt.Errorf("make dst dir: %s", err)
	}
	dstFile, err := os.OpenFile(path.Join(h.Dir, dst), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open dst file: %s", err)
	}
	if err = encode(dstFile, img); err != nil {
		dstFile.Close()
		return fmt.Errorf("encode dst file: %s", err)
	}
	if err = dstFile.Close(); err != nil {
		return fmt.Errorf("close dst file: %s", err)
	}
	return nil
}

func (h *FileHandler) ServeFile(w http.ResponseWriter, name string) {
	ext := path.Ext(name)
	var mime string
	switch ext {
	default:
		fmt.Fprint(w, "404 Not Found")
		return
	case ".jpg":
		mime = "image/jpeg"
	case ".png":
		mime = "image/png"
	}
again:
	file, err := os.Open(path.Join(h.Dir, name))
	if err != nil {
		if os.IsNotExist(err) && strings.HasPrefix(name, "style-large/") {
			if err = h.SaveStyle(name[12:], name, 1200, 1200); err == nil {
				goto again
			} else {
				log.Printf("Style error: %s", err)
			}
		}
		fmt.Fprint(w, "404 Not Found")
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.IsDir() {
		fmt.Fprint(w, "404 Not Found")
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(int(stat.Size())))
	w.Header().Set("Content-Type", mime)
	io.Copy(w, file)
}

type Server struct {
	Domain          string
	TrustProxy      string
	StaticHost      string
	AssetRev        func(asset string, inline bool) (interface{}, error)
	AssetHandler    http.Handler
	TemplateLoader  func(string, *template.FuncMap) (*template.Template, error)
	FileHandler     *FileHandler
	Repo            *Repo
	SessionDuration time.Duration
	secret          []byte
	o               sync.Once
	err             error
	templateFuncMap *template.FuncMap
}

func (s *Server) init() {
	s.err = func() error {
		s.templateFuncMap = &template.FuncMap{
			"asset": func(asset string, inline bool) (interface{}, error) {
				result, err := s.AssetRev(asset, inline)
				if len(s.StaticHost) == 0 || inline {
					return result, err
				}
				if err != nil {
					return result, err
				}
				attr, ok := result.(template.HTMLAttr)
				if !ok {
					return result, nil
				}
				return template.HTMLAttr(fmt.Sprintf("//%s%s", s.StaticHost, string(attr))), nil
			},
			"copyright": func() string {
				since := 2016
				now := time.Now()
				if now.Year() == since {
					return strconv.Itoa(since)
				}
				return fmt.Sprintf("%d-%d", since, now.Year()%100)
			},
			"csrf": s.generateCSRF,
		}
		s.secret = s.Repo.Secret()
		return nil
	}()
}

func (s *Server) generateCSRF(session *Session, seed ...string) string {
	sum := hmac.New(sha512.New, s.secret)
	sum.Write([]byte(session.ID))
	for _, part := range seed {
		io.WriteString(sum, part)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.o.Do(s.init)

	switch {
	case s.err != nil:
		s.serverError(w, r, s.err)
	case r.URL.Path == "/":
		s.home(w, r)
	case r.URL.Path == "/portfolio":
		s.portfolio(w, r)
	case strings.HasPrefix(r.URL.Path, "/portfolio/"):
		s.portfolioView(w, r, r.URL.Path[11:])
	case r.URL.Path == "/about":
		s.about(w, r)
	case r.URL.Path == "/contact":
		s.contact(w, r)
	case r.URL.Path == "/login":
		s.login(w, r)
	case r.URL.Path == "/logout":
		s.logout(w, r)
	case r.URL.Path == "/admin":
		s.admin(w, r)
	case r.URL.Path == "/admin/portfolio":
		s.adminPortfolio(w, r)
	case strings.HasPrefix(r.URL.Path, "/file/"):
		s.file(w, r.URL.Path[6:])
	case r.URL.Path == "/favicon.ico":
		r.URL.Path = "/static/favicon.ico"
		s.asset(w, r)
	case strings.HasPrefix(r.URL.Path, "/static/"):
		s.asset(w, r)
	default:
		s.notFound(w, r)
	}
}

type page struct {
	Page    string
	Session *Session
	User    *User
}

type portfolioPage struct {
	*page
	Items []*Portfolio
}

func (s *Server) tplData(w http.ResponseWriter, r *http.Request, tpl string) *page {
	return &page{
		Page:    tpl,
		Session: s.getSetSession(w, r),
	}
}

type portfolioByPriority []*Portfolio

func (p portfolioByPriority) Len() int           { return len(p) }
func (p portfolioByPriority) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p portfolioByPriority) Less(i, j int) bool { return p[i].Priority > p[j].Priority }

func filterChosen(ps []*Portfolio) []*Portfolio {
	chosen := make([]*Portfolio, 12)
	total := 0
	for _, p := range ps {
		if !p.Chosen {
			continue
		}
		chosen[total] = p
		total++
	}
	chosen = chosen[:total]
	sort.Sort(portfolioByPriority(chosen))
	return chosen
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	tplName := "home"
	tpl := &portfolioPage{
		page:  s.tplData(w, r, tplName),
		Items: filterChosen(s.Repo.Portfolio()),
	}
	s.execTplName(w, r, tplName, tpl)
}

var ErrNoSession = errors.New("no session in request")

func (s *Server) newSession(r *http.Request, user *User) *Session {
	id := ""
	hash := ""
	if user != nil {
		id = user.ID
		hash = hashUser(user, s.secret)
	}
	return &Session{
		ID:       Base62.Generate(12),
		UserID:   id,
		Hash:     hash,
		IssuedAt: time.Now().Unix(),
	}
}

func (s *Server) setSession(w http.ResponseWriter, session *Session) error {
	cookie, err := jwt.MarshalJWT(session, s.secret)
	if err != nil {
		return fmt.Errorf("marshal jwt: %s", err)
	}
	http.SetCookie(w, &http.Cookie{Name: "s", Value: cookie, HttpOnly: true, Domain: s.Domain, Path: "/"})
	return nil
}

func (s *Server) getSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("s")
	if err != nil {
		return nil, ErrNoSession
	}
	session := &Session{}
	if err = jwt.UnmarshalJWT(cookie.Value, session, s.secret); err != nil {
		return nil, fmt.Errorf("unmarshal jwt: %s", err)
	}
	if s.Repo.IsJWTBlacklisted(session.ID) {
		return nil, errors.New("jwt blacklisted")
	}
	if len(session.UserID) != 0 {
		session.User, err = s.Repo.GetUserByID(session.UserID)
		if err != nil {
			return nil, err
		}
		if err != nil {
			return nil, err
		}
		if !hmac.Equal([]byte(hashUser(session.User, s.secret)), []byte(session.Hash)) {
			return nil, errors.New("user password changed")
		}
		activeAt := session.ActiveAt()
		if time.Now().After(activeAt.Add(s.SessionDuration)) {
			return nil, errors.New("jwt expired")
		}
	}

	return session, nil
}

func hashUser(user *User, key []byte) string {
	hashW := hmac.New(sha256.New, key)
	hashW.Write([]byte(user.Password))
	return base64.RawURLEncoding.EncodeToString(hashW.Sum(nil))
}

func (s *Server) getSetSession(w http.ResponseWriter, r *http.Request) *Session {
	session, err := s.getSession(r)
	if err != nil && err != ErrNoSession {
		log.Printf("Session read error: %s", err)
	}
	if session == nil {
		session = s.newSession(r, nil)
		if err = s.setSession(w, session); err != nil {
			log.Printf("Session write error: %s", err)
		}
	} else {
		if time.Now().After(session.ActiveAt().Add(1 * time.Minute)) {
			session.RefreshedAt = time.Now().Unix()
			if err = s.setSession(w, session); err != nil {
				log.Printf("Refresh session error: %s", err)
			}
		}
	}
	return session
}

func (s *Server) portfolio(w http.ResponseWriter, r *http.Request) {
	tpl := "portfolio"
	ps := portfolioByPriority(s.Repo.Portfolio())
	sort.Sort(ps)
	s.execTplName(w, r, tpl, &portfolioPage{
		page:  s.tplData(w, r, tpl),
		Items: ps,
	})
}

type portfolioViewPage struct {
	*page
	*Portfolio
}

func (s *Server) portfolioView(w http.ResponseWriter, r *http.Request, id string) {
	p, err := s.Repo.GetPortfolio(id)
	if err != nil {
		s.notFound(w, r)
		return
	}
	tplName := "portfolio-view"
	tpl := &portfolioViewPage{s.tplData(w, r, tplName), p}
	s.execTplName(w, r, tplName, tpl)
}

func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	s.execTplName(w, r, "about", nil)
}

type contactReq struct {
	Email   string `json:"email"`
	Message string `json:"message"`
}

func (s *Server) contact(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.execTplName(w, r, "contact", nil)
		return
	}
	req := &contactReq{}
	if !s.marshalRequest(w, r, req) {
		s.sendResponse(w, ErrAPIBadRequest)
		return
	}
	if _, err := mail.ParseAddress(req.Email); err != nil {
		s.sendResponse(w, ErrAPIEmailInvalid)
		return
	}
	session, _ := s.getSession(r)
	if session == nil {
		s.sendResponse(w, ErrAPINoSession)
		return
	}
	var args []string
	for _, u := range s.Repo.Users() {
		args = append(args, u.Email)
	}
	cmd := exec.Command("sendmail", args...)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("Subject: Contacted by %s \r\nFrom: contact@%s <contact@%s>\r\nReply-To: %s\r\n\r\n", s.remoteAddr(r), s.Domain, s.Domain, req.Email) + req.Message)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("sendmail error: %s; output: %s", err, string(out))
	}
	s.sendResponse(w, APIOK)
}

type authenticateReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type res struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	req := &authenticateReq{}
	if !s.marshalRequest(w, r, req) {
		s.sendResponse(w, ErrAPIBadRequest)
		return
	}
	if len(req.Password) > 50 {
		s.sendResponse(w, &res{Error: "Password too long."})
		return
	}
	user, err := s.Repo.GetUserByEmail(req.Email)
	if err != nil {
		s.sendResponse(w, &res{Error: "User not found."})
		return
	}
	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		log.Printf("Authentication failed for %s [%s]: %s", req.Email, r.RemoteAddr, err)
		s.sendResponse(w, &res{Error: "Invalid password provided."})
		return
	}
	session, err := s.getSession(r)
	if err == nil && session.User != nil {
		if err = s.Repo.BlacklistJWT(session.ID, session.ActiveAt().Add(s.SessionDuration)); err != nil {
			s.sendResponse(w, &res{Error: "Service temporarily unavailable."})
			return
		}
	}
	session = s.newSession(r, user)
	s.setSession(w, session)
	s.sendResponse(w, APIOK)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	session, err := s.getSession(r)
	if err == nil && session.User != nil && r.URL.Query().Get("token") == s.generateCSRF(session, "logout") {
		s.Repo.BlacklistJWT(session.ID, session.ActiveAt().Add(s.SessionDuration))
		session = s.newSession(r, nil)
		if err = s.setSession(w, session); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	session, err := s.getSession(r)
	if err != nil || session.User == nil {
		s.forbidden(w, r)
		return
	}
	ps := portfolioByPriority(s.Repo.Portfolio())
	sort.Sort(ps)
	tplName := "admin"
	tpl := &adminPage{
		page:  s.tplData(w, r, tplName),
		Items: ps,
	}
	s.execTplName(w, r, tplName, tpl)
}

type editPortfolioReq struct {
	Title  string `json:"title"`
	Chosen bool   `json:"chosen"`
}

type addPortfolioReq struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Images [][]byte `json:"image"`
}

type adminPage struct {
	*page
	Items []*Portfolio
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (s *Server) adminPortfolio(w http.ResponseWriter, r *http.Request) {
	session, err := s.getSession(r)
	if err != nil || session.User == nil {
		s.forbidden(w, r)
		return
	}
	if r.Method == "PUT" {
		id := r.URL.Query().Get("id")
		req := &editPortfolioReq{}
		if !s.marshalRequest(w, r, req) {
			s.sendResponse(w, ErrAPIBadRequest)
			return
		}
		p, err := s.Repo.GetAndLockPortfolio(id)
		if err != nil {
			s.sendResponse(w, ErrAPINotFound)
			return
		}
		fields := r.URL.Query()["field"]
		if contains(fields, "title") {
			p.Title = req.Title
		}
		if contains(fields, "chosen") {
			p.Chosen = req.Chosen
		}
		if err = s.Repo.Commit(); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.sendResponse(w, APIOK)
		return
	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		p, err := s.Repo.GetPortfolio(id)
		if err != nil {
			s.sendResponse(w, ErrAPINotFound)
			return
		}
		if err = s.Repo.DeletePortfolio(id); err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, img := range p.Images {
			if err = s.FileHandler.Remove(img.Name); err != nil && !os.IsNotExist(err) {
				log.Printf("Could not delete portfolio file %s: %s", img.Name, err)
			}
		}
		s.sendResponse(w, APIOK)
		return
	}
	req := &addPortfolioReq{}
	if !s.marshalRequest(w, r, req) {
		s.sendResponse(w, ErrAPIBadRequest)
		return
	}
	var imgs []*Image
	cleanup := func() {
		for _, img := range imgs {
			s.FileHandler.Remove(img.Name)
		}
	}
	for _, i := range req.Images {
		img, err := jpeg.Decode(bytes.NewReader(i))
		mime := "image/jpeg"
		ext := ".jpg"
		if err != nil {
			img, err = png.Decode(bytes.NewReader(i))
			ext = ".png"
			mime = "image/png"
			if err != nil {
				s.sendResponse(w, &res{Error: "Invalid image provided."})
				cleanup()
				return
			}
		}
		name := UUID4().String() + ext
		if err = s.FileHandler.Save(name, i, 0644); err != nil {
			s.sendResponse(w, ErrAPIDiskWrite)
			return
		}
		bounds := img.Bounds().Max
		imgs = append(imgs, &Image{
			Name:   name,
			Height: bounds.X,
			Width:  bounds.Y,
			Mime:   mime,
		})
	}
	p := &Portfolio{
		ID:        UUID4().String(),
		Title:     req.Title,
		Images:    imgs,
		CreatedAt: time.Now(),
		Priority:  time.Now().UnixNano(),
	}
	if err = s.Repo.AddPortfolio(p); err != nil {
		s.sendResponse(w, &res{Error: "Could not update the database."})
		return
	}
	s.sendResponse(w, APIOK)
}

func (s *Server) sendResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Print(err)
	}
}

func (s *Server) marshalRequest(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	decode := func() error {
		return MarshalRequest(v, r)
	}
	if r.Header.Get("Content-Type") == "application/json" {
		decode = func() error {
			return json.NewDecoder(r.Body).Decode(v)
		}
	}
	if err := decode(); err != nil {
		log.Printf("Invalid request: %s", err)
		return false
	}
	return true
}

func (s *Server) execTplName(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	if data == nil {
		data = s.tplData(w, r, name)
	}
	tpl, err := s.TemplateLoader(name, s.templateFuncMap)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.execTpl(w, r, tpl, data)
}

func (s *Server) execTpl(w http.ResponseWriter, r *http.Request, tpl *template.Template, data interface{}) {
	buf := bytes.NewBuffer(nil)
	if err := tpl.Execute(buf, data); err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, err := io.Copy(w, buf); err != nil {
		s.writeError(w, r, err)
	}
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "403 Forbidden", http.StatusForbidden)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("%s %s: write error: %s", r.Method, r.URL.Path, err)
}

func (s *Server) file(w http.ResponseWriter, name string) {
	s.FileHandler.ServeFile(w, name)
}

func (s *Server) remoteAddr(r *http.Request) string {
	addr := r.RemoteAddr
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host != s.TrustProxy {
		return host
	}
	if forwardedFor := r.Header.Get("X-Real-IP"); len(forwardedFor) != 0 {
		return forwardedFor
	}
	return host
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	s.AssetHandler.ServeHTTP(w, r)
}

func MarshalRequest(v interface{}, r *http.Request) error {
	parse := r.ParseForm
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-type")), "multipart/form-data") {
		parse = func() error {
			return r.ParseMultipartForm(10 << 20)
		}
	}
	if err := parse(); err != nil {
		return err
	}
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr {
		return errors.New("v not a pointer")
	}
	for i := 0; i < val.Elem().NumField(); i++ {
		f := val.Elem().Field(i)
		ft := val.Elem().Type().Field(i)
		fieldName := ft.Name
		if jsonTag := ft.Tag.Get("json"); len(jsonTag) != 0 {
			if fieldName = strings.SplitN(jsonTag, ",", 2)[0]; fieldName == "" || fieldName == "-" {
				continue
			}
		}
		if err := marshalField(f, fieldName, r); err != nil {
			return err
		}
	}
	return nil
}

// marshalFieldIndex returns converted form value at index which is one of types: string, int, []byte, nil (no value).
func marshalFieldIndex(kind reflect.Kind, key string, index int, r *http.Request) (interface{}, error) {
	switch kind {
	case reflect.String:
		if vs := r.Form[key]; len(vs) > index {
			return vs[index], nil
		}
		return nil, nil
	case reflect.Int:
		if vs := r.Form[key]; len(vs) > index {
			val, err := strconv.Atoi(vs[index])
			if err != nil {
				return nil, fmt.Errorf("invalid int value for %s: %s", key, err)
			}
			return val, nil
		}
		return nil, nil
	case reflect.Slice:
		// Uploaded file, []uint8.
		if r.MultipartForm == nil || len(r.MultipartForm.File[key]) <= index {
			return nil, nil
		}
		file := r.MultipartForm.File[key][index]
		fr, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("parse uploaded file: %s", err)
		}
		content, err := ioutil.ReadAll(fr)
		fr.Close()
		if err != nil {
			return nil, fmt.Errorf("uploaded file read: %s", err)
		}
		return content, nil
	default:
		return nil, fmt.Errorf("type not supported: %s", kind)
	}
}

func marshalField(f reflect.Value, key string, r *http.Request) error {
	switch f.Kind() {
	case reflect.Slice:
		sliceOf := f.Type().Elem()
		switch sliceOf.Kind() {
		case reflect.Uint8:
			// Uploaded file.
			val, err := marshalFieldIndex(f.Kind(), key, 0, r)
			if err != nil {
				return err
			}
			if val != nil {
				f.Set(reflect.ValueOf(val))
			}
		default:
			// Multiple values of some other type of field.
			if sliceOf.Kind() == reflect.Slice && sliceOf.Elem().Kind() != reflect.Uint8 {
				return fmt.Errorf("only a slice of uint8 is supported, got %s", sliceOf.Elem().Kind())
			}
			val := reflect.New(reflect.SliceOf(sliceOf)).Elem()
			i := 0
			for {
				v, err := marshalFieldIndex(sliceOf.Kind(), key, i, r)
				if err != nil {
					return fmt.Errorf("field %s[%d] value error: %s", key, i, err)
				}
				if v == nil {
					break
				}
				val = reflect.Append(val, reflect.ValueOf(v))
				i++
			}
			if i >= 0 {
				f.Set(val)
			}
		}
	default:
		// Standard (single) field.
		val, err := marshalFieldIndex(f.Kind(), key, 0, r)
		if err != nil {
			return fmt.Errorf("field %s transformation error: %s", key, err)
		}
		if val != nil {
			f.Set(reflect.ValueOf(val))
		}
	}
	return nil
}

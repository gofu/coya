package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofu/coya"
)

var (
	addr       = flag.String("addr", "127.0.0.1:2692", "TCP address to listen on")
	dev        = flag.Bool("dev", false, "enable dev mode")
	host       = flag.String("host", "localhost", "HTTP host")
	fileDir    = flag.String("file-dir", "file", "HTTP host")
	staticHost = flag.String("static-host", "", "HTTP host for static resources")
	trustProxy = flag.String("trust-proxy", "127.0.0.1", "proxy to trust with x-forwarded-for header")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	repo, err := coya.NewRepo("db.json")
	if err != nil {
		log.Fatal(err)
	}

	handler := &coya.Server{
		Repo:            repo,
		SessionDuration: 1 * time.Hour,
		Domain:          *host,
		StaticHost:      *staticHost,
		TrustProxy:      *trustProxy,
		FileHandler: &coya.FileHandler{
			Dir: *fileDir,
		},
	}
	if *dev {
		log.Print("Development mode")
		handler.AssetHandler = http.HandlerFunc(devAssetHandler)
		handler.AssetRev = devInlineRevLoader
		handler.TemplateLoader = templateLoader
	} else {
		log.Print("Production mode")
		handler.AssetHandler = &assets{}
		handler.AssetRev = inlineRevLoader
		handler.TemplateLoader = cachedTemplateLoader
	}

	server := http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       1 * time.Minute,
		WriteTimeout:      1 * time.Minute,
		Handler:           handler,
	}

	log.Printf("Listening on http://%s", ln.Addr())
	serveC := make(chan error, 1)
	go func() {
		serveC <- server.Serve(ln)
	}()

	select {
	case err = <-serveC:
		log.Fatalf("HTTP serve error: %s", err)
	case <-sig:
		log.Print("SIGINT received, shutting down")
		timeout := 70 * time.Second
		if *dev {
			timeout = 0
		}
		ctx, done := context.WithTimeout(context.Background(), timeout)
		if err = server.Shutdown(ctx); err != nil {
			log.Fatalf("HTTP server shutdown error: %s", err)
		}
		done()
	}
}

var revCache sync.Map

type revCacheItem struct {
	attr   template.HTMLAttr
	inline interface{}
}

func inlineRevLoader(asset string, inline bool) (interface{}, error) {
	rev, ok := revCache.Load(asset)
	if ok {
		if inline {
			return rev.(*revCacheItem).inline, nil
		}
		return rev.(*revCacheItem).attr, nil
	}
	content, err := coya.Asset(asset[1:])
	if err != nil {
		return "", err
	}
	hash := md5.Sum(content)
	ext := path.Ext(asset)
	if ext == ".css" {
		content = coya.RevCSSRegexp.ReplaceAllFunc(content, coya.RevAsset)
	}
	assetRev := template.HTMLAttr(fmt.Sprintf("%s-%x%s", asset[:len(asset)-len(ext)], hash, ext))
	item := &revCacheItem{attr: assetRev, inline: inlineContentTypeByExt(content, ext)}
	revCache.Store(asset, item)

	if inline {
		return item.inline, nil
	}
	return item.attr, nil
}
func inlineContentTypeByExt(content []byte, ext string) interface{} {
	switch ext {
	case ".css":
		return template.CSS(content)
	case ".js":
		return template.JS(content)
	default:
		return string(content)
	}
}

func devInlineRevLoader(asset string, inline bool) (interface{}, error) {
	if inline {
		content, err := devAssetContent(asset[1:])
		if err != nil {
			return "", err
		}
		return inlineContentTypeByExt(content, path.Ext(asset)), nil
	}
	return template.HTMLAttr(asset), nil
}

var hashRegexp = regexp.MustCompile(`-[a-f0-9]{32}`)

type assets struct {
	cache sync.Map
}

type asset struct {
	eTag        string
	contentType string
	modTime     time.Time
	content     []byte
	contentGzip []byte
	contentDefl []byte
}

func (a *asset) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(a.eTag) != 0 && r.Header.Get("If-None-Match") == a.eTag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if ifModSince := r.Header.Get("If-Modified-Since"); len(ifModSince) != 0 {
		if cachedSince, err := time.Parse(time.RFC1123, ifModSince); err == nil && a.modTime.After(cachedSince) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("ETag", a.eTag)
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Expires", time.Now().Add(24*30*time.Hour).Format(time.RFC1123))
	if !a.modTime.IsZero() {
		w.Header().Set("Last-Modified", a.modTime.Format(time.RFC1123))
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "flate") {
		w.Header().Set("Content-Length", strconv.Itoa(len(a.contentDefl)))
		w.Header().Set("Content-Encoding", "deflate")
		io.Copy(w, bytes.NewReader(a.contentDefl))
	} else if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Length", strconv.Itoa(len(a.contentGzip)))
		w.Header().Set("Content-Encoding", "gzip")
		io.Copy(w, bytes.NewReader(a.contentGzip))
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(a.content)))
		io.Copy(w, bytes.NewReader(a.content))
	}
}

func (a *assets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	asset := hashRegexp.ReplaceAllString(r.URL.Path[1:], "")
	if h, ok := a.cache.Load(asset); ok {
		h.(http.Handler).ServeHTTP(w, r)
		return
	}
	content, err := coya.Asset(asset)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := typeByExtension(path.Ext(r.URL.Path))
	var modTime time.Time
	if stat, err := coya.AssetInfo(asset); err == nil {
		modTime = stat.ModTime()
	}
	h := a.makeHandler(contentType, content, modTime)
	a.cache.Store(asset, h)
	h.ServeHTTP(w, r)
}

func (a *assets) makeHandler(contentType string, content []byte, modTime time.Time) http.Handler {
	if contentType == "text/css" {
		content = coya.RevCSSRegexp.ReplaceAllFunc(content, coya.RevAsset)
	}
	contentHash := md5.Sum(content)
	contentETag := fmt.Sprintf(`"%s"`, hex.EncodeToString(contentHash[:]))

	// GZIP
	contentGzipBuf := bytes.NewBuffer(nil)
	gzipW := gzip.NewWriter(contentGzipBuf)
	io.Copy(gzipW, bytes.NewReader(content))
	gzipW.Close()
	contentGzip := contentGzipBuf.Bytes()

	// Deflate
	contentDeflBuf := bytes.NewBuffer(nil)
	deflW, _ := flate.NewWriter(contentDeflBuf, -1)
	io.Copy(deflW, bytes.NewReader(content))
	deflW.Close()
	contentDefl := contentDeflBuf.Bytes()

	return &asset{
		eTag:        contentETag,
		contentType: contentType,
		content:     content,
		contentGzip: contentGzip,
		contentDefl: contentDefl,
		modTime:     modTime,
	}
}

func devAssetContent(asset string) ([]byte, error) {
	if strings.HasPrefix(asset, "static/") {
		content, err := coya.Asset("ui/" + asset[7:])
		if err == nil {
			return content, nil
		}
	}
	content, err := coya.Asset(asset)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func devAssetHandler(w http.ResponseWriter, r *http.Request) {
	content, err := devAssetContent(r.URL.Path[1:])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := typeByExtension(path.Ext(r.URL.Path))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("Cache-Control", "no-cache")
	io.Copy(w, bytes.NewReader(content))
}

func templateLoader(name string, funcs *template.FuncMap) (*template.Template, error) {
	rootContent, err := coya.Asset("tpl/root.gohtml")
	if err != nil {
		return nil, err
	}
	tplContent, err := coya.Asset(path.Join("tpl", name+".gohtml"))
	if err != nil {
		return nil, err
	}
	tpl, err := template.New("").Funcs(*funcs).Parse(string(rootContent))
	if err != nil {
		return nil, err
	}
	tpl, err = tpl.Parse(string(tplContent))
	if err != nil {
		return nil, err
	}
	return tpl, nil
}

var tplCache sync.Map

func cachedTemplateLoader(name string, funcs *template.FuncMap) (*template.Template, error) {
	tpl, ok := tplCache.Load(name)
	if ok == true {
		return tpl.(*template.Template), nil
	}

	var err error
	tpl, err = templateLoader(name, funcs)
	if err != nil {
		return nil, err
	}

	tplCache.Store(name, tpl)
	return tpl.(*template.Template), nil
}

func typeByExtension(ext string) string {
	switch ext {
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".jpg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".svg":
		return "image/svg+xml"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

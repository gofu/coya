package coya

import (
	"crypto/md5"
	"encoding/hex"
	"path"
	"regexp"
)

var (
	RevCSSRegexp = regexp.MustCompile(`(url\s*\(\s*/?)(.+?)(\))`)
)

func RevAsset(p []byte) []byte {
	matches := RevCSSRegexp.FindAllStringSubmatch(string(p), -1)
	if len(matches) < 1 || len(matches[0]) < 4 {
		return p
	}
	name := matches[0][2]
	var content []byte
	content, err := Asset(name)
	if err != nil {
		return p
	}
	assetHash := md5.Sum(content)
	ext := path.Ext(name)
	return []byte(matches[0][1] + name[:len(name)-len(ext)] + "-" + hex.EncodeToString(assetHash[:]) + ext + matches[0][3])
}

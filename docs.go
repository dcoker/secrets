// Code generated by go-bindata.
// sources:
// docs/usage.txt
// DO NOT EDIT!

package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _docsUsageTxt = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\x8c\x54\x41\x6f\xdb\x38\x13\x3d\x9b\xbf\x62\x50\xe4\xd0\xa2\x96\x8b\x2f\xed\xb7\x8b\x15\xd0\x83\xeb\x78\x03\x23\x71\x12\xd8\x29\x8a\x02\x0b\x04\xb4\x34\x92\x88\x48\xa4\x4a\x52\x71\xb4\x41\xfe\xfb\x3e\x8a\x8a\xeb\x62\x17\xdb\xf5\xc5\x22\x39\xf3\x66\xe6\xcd\xbc\x99\xd3\xe2\x72\x45\x85\xb1\xd4\x48\x2d\x4b\xa5\x4b\x72\x9c\x59\xf6\x6e\x26\xc4\x36\x7e\x91\xb4\x4c\xac\x33\xdb\xb7\x9e\x73\xda\x2b\x5f\x91\xd4\xc4\x6d\xc5\x0d\x5b\x59\xd3\x3d\xf7\xd1\x1d\xaf\xbb\x9e\x2e\xd6\xdb\x19\xdd\x56\x2c\x32\x05\x13\xeb\xf9\x71\xc4\x70\xde\x58\x98\x28\x4d\x92\x6a\x93\xc1\xf3\xeb\x7c\x7d\x49\x85\xaa\x99\x7c\x25\x3d\x29\x47\x4e\x16\x38\x18\xca\x95\xf3\x56\xed\x3a\xcf\xc1\xde\x99\xce\x66\x4c\x99\xd1\xde\x9a\x7a\x2a\x72\x6e\x6b\xd3\x37\xac\xbd\x9b\xd2\x62\x45\xae\x77\x9e\x1b\x7c\xb3\xcf\x90\xf8\xad\x89\xb1\xa8\x87\x1f\xf0\xad\xf3\x63\x59\xa9\x10\x93\x93\x97\x12\x29\x29\xa8\xb0\xc0\x64\x9d\xcf\xfa\xa6\xa6\xe4\x1e\x79\xea\x54\xee\x5d\x7a\xdf\xb8\xb4\x73\xc9\x9e\x9d\x9f\xcd\x66\x29\x4a\x7c\x77\xfa\xa1\xc0\x27\xb5\x9d\xa7\x7c\x77\xd7\x39\xb6\x5a\x36\x1c\xce\x4a\x07\xd4\x0c\x15\x1c\xc3\x89\xc9\x91\x59\x2a\x26\x13\x80\xdc\xa9\x3c\xfd\x79\x8c\xd1\x36\x72\x6a\x53\x82\xe1\x78\xf5\x9d\xd2\x94\x16\xea\xd3\x6f\xf6\xfd\xe7\xb7\xd6\x3e\x2c\x3f\x5d\x5c\xbe\xfb\x95\x55\xf4\x95\x75\x69\x2c\xba\xd4\xa4\x63\xa5\x3b\xf3\x88\xeb\x63\x5f\xae\x6e\xfe\x5c\x7e\x5e\xbb\xcd\xe6\xe6\x6d\x70\x12\xd7\xad\x57\x46\xcb\xba\xee\xc9\x34\xca\xa3\x1f\x3c\xf4\x75\x5f\xb1\x1e\xc8\x1c\x46\xa3\xdb\x39\xfe\xd6\x81\xf6\x17\x0a\xff\x9d\xcf\x91\xaa\x56\x3a\xb7\x37\x36\xa7\xff\x9d\xbe\xff\x30\x74\xc7\xb2\xcc\xff\x1b\x44\xc9\x3f\x40\x88\x49\xc4\xf8\xe7\xd1\x1c\x86\x0a\x15\x74\xee\xfb\x20\xa3\x76\x7a\x7d\x25\x17\xf5\x1b\xc2\x94\xcf\x97\xdb\xe4\x7c\xb1\x4e\x4e\xff\xff\x0b\x8a\xbe\x31\xb5\xca\x14\xbb\xf0\x72\x6e\xa5\x0e\x80\xde\xcb\xac\x02\x16\x66\x10\x83\x1c\x38\x70\x94\xb3\x67\xdb\x28\xcd\xa0\x43\x65\x15\xad\xe6\x6b\x0a\x8d\x0d\x8e\x02\x03\xc9\x31\x11\xc4\x36\xfb\xe8\xda\xb2\x85\xa8\x9a\x97\xdc\x40\x2d\x24\x93\x03\xe8\x70\x34\x30\x91\xe1\xcb\x51\xa7\x73\xb6\x24\x85\x6b\x39\x53\x85\xca\x42\xd0\x19\x7d\x41\x0b\x8f\xf4\x08\xce\xbe\x75\xca\x22\x54\x18\x9b\x73\xd6\xc1\x9d\xcf\xa4\x97\x17\xdc\x4f\x07\xf4\xc0\xea\x91\x87\xf8\xc1\xe3\x2c\x86\xfe\xa9\xac\x97\x87\x8c\x17\xa1\x0d\x8f\x9e\x4c\x41\x4f\xaf\xa2\xd3\x2a\x7f\x95\x52\x18\xe7\xe7\xe9\x48\xc5\x50\xb3\x13\x05\xc8\x49\x4a\x2b\xf1\x97\x53\x19\xa9\x44\x64\x48\x38\xf3\x91\x91\x43\x71\x87\x7a\x24\x66\xcc\x06\xe1\xeb\xf0\x0e\xa0\xc3\xd3\x21\x2b\x31\x52\x13\x19\xb9\xad\xb0\x20\xf8\x51\x36\x2d\x16\x06\x2c\x51\x3f\xaa\x88\xe1\x62\x22\xa1\x7a\xc0\xcd\x37\x57\xf4\xda\x75\x21\x3d\x17\xce\xa1\x5f\x1b\xb4\x29\xf4\x39\xf4\xed\xcd\xb0\x61\x22\x21\xc2\x68\x4c\x8c\xa4\x30\x32\xb0\x78\x90\x75\x07\xb1\x0a\xc2\xef\x84\xa0\xd2\x40\xde\x18\x2c\x89\x91\x92\x04\xd9\x24\x2a\xa7\x93\xa7\x8b\xe5\xd7\xbb\xd5\xd9\x33\xae\x86\x27\xe6\xa4\x85\x50\x20\x34\xec\xb6\x93\x27\xa4\xf1\x4c\x7f\x0c\x50\xe1\x97\x24\x47\x3d\x1f\xdb\x81\x4b\x2c\x35\xf0\x04\xe6\x50\xf8\xdf\xc8\xdf\x06\xc5\xf9\x8f\x4f\x2f\xf4\x7f\x3c\xd2\xc2\xb3\x10\x73\x90\x16\xa6\xf4\x08\x38\x74\xb5\x36\x65\x19\x59\x5f\xd4\xa6\xcb\x6f\x81\x5e\xa3\xf1\x67\xdc\x42\x56\x81\x23\xcc\xdf\xb0\x1a\x5b\x69\xbd\xca\xba\x5a\x42\x19\x5f\xb6\x61\xbf\x16\xaa\xec\x22\xd4\x34\x98\x60\xaf\xf7\xa4\x79\x6c\x21\x0f\x7b\x41\xc0\xf4\x6e\xb3\x3c\x5f\x5d\x5f\x0d\x92\xc2\xe9\x66\x73\xfd\xfb\xea\x72\x89\xc6\x3d\x28\xa8\x37\x2c\x66\x30\x69\x95\xdc\x41\x1b\x33\xf1\x57\x00\x00\x00\xff\xff\x23\x2e\x2d\xb5\x66\x06\x00\x00")

func docsUsageTxtBytes() ([]byte, error) {
	return bindataRead(
		_docsUsageTxt,
		"docs/usage.txt",
	)
}

func docsUsageTxt() (*asset, error) {
	bytes, err := docsUsageTxtBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "docs/usage.txt", size: 1638, mode: os.FileMode(436), modTime: time.Unix(1447134097, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"docs/usage.txt": docsUsageTxt,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"docs": {nil, map[string]*bintree{
		"usage.txt": {docsUsageTxt, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

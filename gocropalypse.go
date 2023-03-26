// Based on https://github.com/infobyte/CVE-2023-21036
// Based on https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const PNG_MAGIC = "\x89PNG\r\n\x1a\n"

func parsePngChunk(stream io.Reader) (string, []byte, error) {
  var size uint32
  err := binary.Read(stream, binary.BigEndian, &size)
  if err != nil {
    return "", nil, err
  }

  ctype := make([]byte, 4)
  _, err = stream.Read(ctype)
  if err != nil {
    return "", nil, err
  }

  body := make([]byte, size)
  _, err = stream.Read(body)
  if err != nil {
    return "", nil, err
  }

  var csum uint32
  err = binary.Read(stream, binary.BigEndian, &csum)
  if err != nil {
    return "", nil, err
  }

  calculatedCsum := crc32.ChecksumIEEE(append(ctype, body...))
  if calculatedCsum != csum {
    return "", nil, fmt.Errorf("checksum mismatch")
  }

  return string(ctype), body, nil
}

func validPngIend(trailer []byte) bool {
  if len(trailer) < 12 {
    return false
  }

  iendPos := len(trailer) - 8
  iendSize := binary.BigEndian.Uint32(trailer[iendPos-4 : iendPos])
  iendCsum := binary.BigEndian.Uint32(trailer[iendPos+4 : iendPos+8])
  return iendSize == 0 && iendCsum == 0xAE426082
}

func parseJpeg(fIn io.Reader) ([]byte, error) {
  SOI_MARKER := []byte{0xFF, 0xD8}
  APP0_MARKER := []byte{0xFF, 0xE0}

  // Read SOI marker
  soiMarker := make([]byte, 2)
  _, err := fIn.Read(soiMarker)
  if err != nil {
    return nil, err
  }
  if !bytes.Equal(soiMarker, SOI_MARKER) {
    return nil, errors.New("invalid SOI marker")
  }

  // Read APP0 marker
  app0Marker := make([]byte, 2)
  _, err = fIn.Read(app0Marker)
  if err != nil {
    return nil, err
  }
  if !bytes.Equal(app0Marker, APP0_MARKER) {
    return nil, nil
  }

  // Read APP0 size
  var app0Size uint16
  err = binary.Read(fIn, binary.BigEndian, &app0Size)
  if err != nil {
    return nil, err
  }

  // Read APP0 body
  app0Body := make([]byte, app0Size-2)
  _, err = fIn.Read(app0Body)
  if err != nil {
    return nil, err
  }
  if !bytes.Equal(app0Body[:4], []byte("JFIF")) {
    return nil, errors.New("invalid JFIF signature")
  }

  fileContent, err := ioutil.ReadAll(fIn)
  if err != nil {
    return nil, err
  }

  eoiMarkerPos := bytes.Index(fileContent, []byte{0xFF, 0xD9})
  if eoiMarkerPos == -1 {
    return nil, errors.New("EOI marker not found")
  }

  trailer := fileContent[eoiMarkerPos+2:]

  if len(trailer) > 0 && bytes.Equal(trailer[len(trailer)-2:], []byte{0xFF, 0xD9}) {
    return trailer, nil
  }

  return nil, nil
}

func parsePng(f_in io.Reader) ([]byte, error) {
  magic := make([]byte, len(PNG_MAGIC))
  _, err := f_in.Read(magic)
  if err != nil {
    return nil, err
  }

  if !bytes.Equal(magic, []byte(PNG_MAGIC)) {
    return nil, fmt.Errorf("invalid PNG magic number")
  }

  for {
    ctype, _, err := parsePngChunk(f_in)
    if err != nil {
      return nil, err
    }

    if ctype == "IEND" {
      break
    }
  }

  trailer, err := ioutil.ReadAll(f_in)
  if err != nil {
    return nil, err
  }
  return trailer, nil
}

func isConfirmedImgFile(file string) bool {
  ext := strings.ToLower(filepath.Ext(file))
  return ext == ".png" || ext == ".jpg"
}

func appendConfirmedImgFiles(path string, confirmedPngFiles *[]string) error {
  files, err := os.ReadDir(path)
  if err != nil {
    return err
  }

  for _, file := range files {
    fullPath := filepath.Join(path, file.Name())
    if file.IsDir() {
      if !strings.HasPrefix(file.Name(), ".") { // Ignore hidden directories
        err = appendConfirmedImgFiles(fullPath, confirmedPngFiles)
        if err != nil {
          return err
        }
      }
    } else {
      if isConfirmedImgFile(fullPath) {
        *confirmedPngFiles = append(*confirmedPngFiles, fullPath)
      }
    }
  }

  return nil
}

func main() {
  startTime := time.Now()
  vulnCount := 0
  args := os.Args[1:]
  if len(args) < 1 {
    fmt.Println("go run gocropalypse.go /path/to/dir")
    return
  }

  directory := args[0]
  var imgFiles []string
  err := appendConfirmedImgFiles(directory, &imgFiles)
  if err != nil {
    fmt.Println("Error:", err)
    return
  }

  for _, file := range imgFiles {
    f_in, err := os.Open(file)
    var start [2]byte
    _, err = f_in.Read(start[:])
    if err != nil && err != io.EOF {
      fmt.Println("Error:", err)
    }

    _, err = f_in.Seek(0, io.SeekStart)
    if err != nil {
      fmt.Println("Error:", err)
    }

    // Determine which parser to use for image
    // Handle png
    if bytes.Equal(start[:], []byte("\x89P")) {
      trailer, err := parsePng(f_in)
      if err != nil {
        fmt.Println("Error:", err)
        continue
      }
  
      if len(trailer) > 0 && validPngIend(trailer) {
        fmt.Printf("Potentially vulnerable: %s\n", file)
        vulnCount++
      }

    // Handle jpeg
    } else if bytes.Equal(start[:], []byte("\xFF\xD8")) {
      trailer, err := parseJpeg(f_in)
      if err != nil {
        fmt.Println("Error:", err)
        continue
      }
      if len(trailer) > 0 && bytes.Equal(trailer[len(trailer)-2:], []byte{0xFF, 0xD9}) {
        fmt.Printf("Potentially vulnerable: %s\n", file)
        vulnCount++
      }
    }
    f_in.Close()
  }
  elapsedTime := time.Since(startTime)
  formattedElapsedTime := fmt.Sprintf("%.5f", elapsedTime.Seconds())
  fmt.Printf("Found %d vulnerable images out of a scanned total of %d.\n", vulnCount, len(imgFiles))
  fmt.Printf("Total time to execute: %s seconds\n", formattedElapsedTime)
}
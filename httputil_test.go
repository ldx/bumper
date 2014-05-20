package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "strings"
    "testing"
)

type testWriter struct {
    io.Writer
    buf []byte
}

func (tw *testWriter) Write(p []byte) (n int, err error) {
    tw.buf = p
    return len(p), nil
}

func TestSendResp(t *testing.T) {
    log.SetOutput(noLog{})

    w := new(testWriter)

    SendResp("", w, 200, "", true)
    if strings.Trim(string(w.buf), "\r\n") != "" {
        t.Error(fmt.Sprintf("Invalid response '%s'", string(w.buf)))
    }

    sc := map[int]string{
        100: "Code 100",
        101: "Code 101",
        201: "Code 201",
        301: "Code 301",
        401: "Code 401",
        501: "Code 501",
    }

    SendResp("", w, 200, "", true)
    if strings.Trim(string(w.buf), "\r\n") != "" {
        t.Error(fmt.Sprintf("Invalid response '%s'", string(w.buf)))
    }

    for k, v := range sc {
        SendResp("", w, k, v, false)
        if !strings.Contains(string(w.buf), v) {
            t.Error(fmt.Sprintf("Invalid response '%s'", string(w.buf)))
        }
    }
}

func TestFixRequestHttp(t *testing.T) {
    req, err := http.NewRequest("GET", "http://localhost:80", nil)
    if err != nil {
        t.Error(err)
    }

    err = FixRequest(req, "", false)
    if err != nil {
        t.Error(err)
    }
    if req.URL.String() != "http://localhost:80" {
        t.Error(fmt.Sprintf("Invalid URI in request %s", req))
    }

    if req.Header.Get("X-Orig-Uri") != "" {
        t.Error(fmt.Sprintf("X-Orig-Uri found in %s", req))
    }
}

func TestFixRequestHttpOrigUri(t *testing.T) {
    req, err := http.NewRequest("GET", "http://localhost:80", nil)
    if err != nil {
        t.Error(err)
    }

    err = FixRequest(req, "", true)
    if err != nil {
        t.Error(err)
    }

    if req.Header.Get("X-Orig-Uri") == "" {
        t.Error(fmt.Sprintf("No X-Orig-Uri header found in %s", req))
    }
}

func TestFixRequestHttps(t *testing.T) {
    req, err := http.NewRequest("CONNECT", "localhost:80", nil)
    if err != nil {
        t.Error(err)
    }

    err = FixRequest(req, "localhost:80", false)
    if err != nil {
        t.Error(err)
    }
    if req.URL.String() != "https://localhost:80" {
        t.Error(fmt.Sprintf("Invalid URI in request %s", req))
    }

    if req.Header.Get("X-Orig-Uri") != "" {
        t.Error(fmt.Sprintf("X-Orig-Uri found in %s", req))
    }
}

func TestFixRequestHttpsOrigUri(t *testing.T) {
    req, err := http.NewRequest("CONNECT", "localhost:80", nil)
    if err != nil {
        t.Error(err)
    }

    err = FixRequest(req, "localhost:80", true)
    if err != nil {
        t.Error(err)
    }
    if req.URL.String() != "https://localhost:80" {
        t.Error(fmt.Sprintf("Invalid URI in request %s", req))
    }

    if req.Header.Get("X-Orig-Uri") == "" {
        t.Error(fmt.Sprintf("No X-Orig-Uri header found in %s", req))
    }
}

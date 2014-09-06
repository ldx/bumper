package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

type lengthFixReadCloser struct {
	io.Reader
	io.Closer
}

func FixRequest(req *http.Request, orig_uri string, addhdr bool) (err error) {
	if orig_uri != "" {
		uri, err := url.Parse("https://" + orig_uri + req.RequestURI)
		if err != nil {
			return err
		}
		//log.Printf("Fixing request: %s -> %s\n",
		//	req.URL.String(), uri.String())

		req.URL = uri
		req.RequestURI = ""
	}

	if addhdr {
		req.Header.Set("X-Orig-Uri", req.URL.String())
	}

	keepalive := req.Header.Get("Proxy-Connection")
	if keepalive != "" {
		req.Header.Del("Proxy-Connection")
		req.Header.Set("Connection", keepalive)
	}

	return nil
}

//
// Work around a bug in the go http package.
//
// From: https://github.com/fitstar/falcore/blob/a3c31f03fec11a62d3f49d016b041d1924cd997a/server.go#L297-L331
//
func FixResponse(res *http.Response) (err error) {
	// The res.Write omits Content-length on 0 length bodies, and by spec,
	// it SHOULD. While this is not MUST, it's kinda broken. See sec 4.4
	// of rfc2616 and a 200 with a zero length does not satisfy any of the
	// 5 conditions if Connection: keep-alive is set :(
	// I'm forcing chunked which seems to work because I couldn't get the
	// content length to write if it was 0.
	// Specifically, the android http client waits forever if there's no
	// content-length instead of assuming zero at the end of headers. der.
	if res.Body == nil {
		if res.Request.Method != "HEAD" {
			res.ContentLength = 0
		}
		res.TransferEncoding = []string{"identity"}
		res.Body = ioutil.NopCloser(bytes.NewBuffer([]byte{}))
	} else if res.ContentLength == 0 &&
		len(res.TransferEncoding) == 0 &&
		!((res.StatusCode-100 < 100) ||
			res.StatusCode == 204 ||
			res.StatusCode == 304) {
		// The following is copied from net/http/transfer.go. from stdlib,
		// this is only applied to a request. we need it on a response.

		// Test to see if it's actually zero or just unset.
		var buf [1]byte
		n, _ := io.ReadFull(res.Body, buf[:])
		if n == 1 {
			// Oh, guess there is data in this Body Reader after all.
			// The ContentLength field just wasn't set.
			// Stich the Body back together again, re-attaching our
			// consumed byte.
			res.ContentLength = -1
			res.Body = &lengthFixReadCloser{
				io.MultiReader(bytes.NewBuffer(buf[:]), res.Body),
				res.Body,
			}
		} else {
			res.TransferEncoding = []string{"identity"}
		}
	}
	if res.ContentLength < 0 && res.Request.Method != "HEAD" {
		res.TransferEncoding = []string{"chunked"}
	}

	return nil
}

func SendResp(cli string, w io.Writer, code int, err string, nobody bool) {
	var statusstr string
	switch code {
	case 100:
		statusstr = "Continue"
	case 101:
		statusstr = "Switching Protocols"
	case 200:
		statusstr = "OK"
	case 201:
		statusstr = "Created"
	case 202:
		statusstr = "Accepted"
	case 203:
		statusstr = "Non-Authorative Information"
	case 204:
		statusstr = "No Content"
	case 205:
		statusstr = "Reset Content"
	case 206:
		statusstr = "Partial Content"
	case 301:
		statusstr = "Moved Permanently"
	case 302:
		statusstr = "Found"
	case 303:
		statusstr = "See Other"
	case 307:
		statusstr = "Temporary Redirect"
	case 400:
		statusstr = "Bad Request"
	case 401:
		statusstr = "Authorization Required"
	case 402:
		statusstr = "Payment Required"
	case 403:
		statusstr = "Forbidden"
	case 404:
		statusstr = "Not Found"
	case 405:
		statusstr = "Not Allowed"
	case 406:
		statusstr = "Not Acceptable"
	case 408:
		statusstr = "Request Timeout"
	case 409:
		statusstr = "Conflict"
	case 410:
		statusstr = "Gone"
	case 411:
		statusstr = "Length Required"
	case 412:
		statusstr = "Precondition Failed"
	case 413:
		statusstr = "Request Entity Too Large"
	case 414:
		statusstr = "Request-URI Too Large"
	case 415:
		statusstr = "Unsupported Media Type"
	case 416:
		statusstr = "Requested Range Not Satisfiable"
	case 500:
		statusstr = "Internal Server Error"
	case 501:
		statusstr = "Not Implemented"
	case 502:
		statusstr = "Bad Gateway"
	case 503:
		statusstr = "Service Temporarily Unavailable"
	default:
		log.Printf("Warning: got invalid HTTP status code %d\n", code)
		return
	}

	status := fmt.Sprintf("%d %s", code, statusstr)

	var body string
	if nobody {
		body = ""
	} else {
		body = fmt.Sprintf("<html><head><title>%s</title>\n"+
			"<body>\n"+
			"<h1>%s</h1>\n"+
			"%s\n"+
			"</body>\n"+
			"</html>\n",
			status, status, err)
	}

	resp := http.Response{
		Status:        status,
		StatusCode:    code,
		Proto:         "HTTP/1.0",
		ProtoMajor:    1,
		ProtoMinor:    0,
		Body:          ioutil.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       nil,
		Header:        make(map[string][]string),
	}
	resp.Header.Set("Content-Type", "text/html; charset=UTF-8")
	resp.Header.Set("Content-Length", string(len(body)))
	resp.Header.Set("Date", time.Now().Format(http.TimeFormat))
	resp.Header.Set("Server", "BumperProxy")

	resp.Write(w)

	log.Printf("(%s) <- %s\n", cli, status)
}

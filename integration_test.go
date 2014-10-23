package main

import (
	"bufio"
	"code.google.com/p/go.net/websocket"
	"crypto/tls"
	"github.com/elazarl/goproxy"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"testing"
)

func handler(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "Hello world!\n")
}

func wsEchoHandler(ws *websocket.Conn) {
	io.Copy(ws, ws)
}

func createConfig(certfile string, keyfile string, parent string) (
	bumper *BumperProxy, err error) {
	bumper = new(BumperProxy)

	// Sensible defaults.
	bumper.proxy = parent
	bumper.addorig = false
	bumper.skipverify = true
	bumper.timeout = 60

	// Set up certificate stuff.
	cacert, err := ReadCert(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	bumper.cacert = *cacert
	bumper.maxserial = bumper.cacert.Leaf.SerialNumber.Int64()

	tmpdir, err := ioutil.TempDir("", "bumper")
	if err != nil {
		return nil, err
	}
	bumper.certdir = tmpdir

	bumper.certs = make(map[string]*tls.Certificate)

	bumper.mutex = new(sync.RWMutex)

	return bumper, nil
}

func startBumper(t *testing.T, addr string, parent string) net.Listener {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Error("Listen: ", err)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Error("Accept: ", err)
		}

		bumper, err := createConfig("cybervillains.crt", "cybervillains.key",
			parent)
		if err != nil {
			t.Error("createConfig: ", err)
		}

		handleClient(conn, bumper)
	}()

	return listener
}

func proxyVia(t *testing.T, url string, proxy string) *http.Response {
	tr, err := newTransport(proxy, true)
	if err != nil {
		t.Error("newTransport: ", err)
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", url, nil)
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		t.Error("RoundTrip: ", err)
	}
	if resp.StatusCode != 200 {
		t.Error("RoundTrip failed, response: ", resp)
	}

	return resp
}

func doTestHttp(t *testing.T, parent string) {
	log.SetOutput(noLog{})

	addr := "localhost:12345"

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Error("Listen: ", err)
	}
	defer listener.Close()

	go func() {
		http.Serve(listener, http.HandlerFunc(handler))
	}()

	bumperaddr := "localhost:12346"
	bumperlistener := startBumper(t, bumperaddr, parent)
	defer bumperlistener.Close()

	proxyVia(t, "http://"+addr, bumperaddr)
}

func doTestHttps(t *testing.T, parent string) {
	log.SetOutput(noLog{})

	addr := "localhost:12345"

	plainlistener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Error("Listen: ", err)
	}
	defer plainlistener.Close()

	cert, err := ReadCert("server.crt", "server.key")
	tlsconfig := &tls.Config{
		NextProtos:   []string{"HTTP/1.1"},
		Certificates: []tls.Certificate{*cert},
	}

	listener := tls.NewListener(plainlistener, tlsconfig)
	go func() {
		http.Serve(listener, http.HandlerFunc(handler))
	}()

	bumperaddr := "localhost:12346"
	bumperlistener := startBumper(t, bumperaddr, parent)
	defer bumperlistener.Close()

	resp := proxyVia(t, "https://"+addr, bumperaddr)
	issuer := resp.TLS.PeerCertificates[0].Issuer
	if issuer.Country[0] != "US" ||
		issuer.Organization[0] != "CyberVillians.com" ||
		issuer.OrganizationalUnit[0] != "CyberVillians Certification Authority" {
		t.Error("Invalid issuer in peer certificate: ", issuer)
	}
}

func startParentProxy(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	parent := goproxy.NewProxyHttpServer()
	parent.Verbose = false
	go func() {
		http.Serve(listener, parent)
	}()

	return listener, nil
}

func TestHttp(t *testing.T) {
	doTestHttp(t, "")
}

func TestHttps(t *testing.T) {
	doTestHttps(t, "")
}

func TestHttpParentproxy(t *testing.T) {
	log.SetOutput(noLog{})

	parent := "localhost:12344"
	listener, err := startParentProxy(parent)
	if err != nil {
		t.Error("Listen: ", err)
	}
	defer listener.Close()

	doTestHttp(t, parent)
}

func TestHttpsParentproxy(t *testing.T) {
	log.SetOutput(noLog{})

	parent := "localhost:12344"
	listener, err := startParentProxy(parent)
	if err != nil {
		t.Error("Listen: ", err)
	}
	defer listener.Close()

	doTestHttps(t, parent)
}

func TestWsViaParentproxy(t *testing.T) {
	log.SetOutput(noLog{})

	wsaddr := "localhost:12343"
	wslistener, err := net.Listen("tcp", wsaddr)
	go func() {
		http.Serve(wslistener, websocket.Handler(wsEchoHandler))
	}()
	defer wslistener.Close()

	parentaddr := "localhost:12344"
	listener, err := startParentProxy(parentaddr)
	if err != nil {
		t.Error("Listen: ", err)
	}
	defer listener.Close()

	bumperaddr := "localhost:12346"
	bumperlistener := startBumper(t, bumperaddr, parentaddr)
	defer bumperlistener.Close()

	conn, err := net.Dial("tcp", bumperaddr)
	if err != nil {
		t.Error("Dial: ", err)
	}
	defer conn.Close()

	conn.Write([]byte("CONNECT " + wsaddr + " HTTP/1.1\r\n" +
		"Host: " + wsaddr + "\r\n\r\n"))
	req, err := http.NewRequest("CONNECT", wsaddr, nil)
	if err != nil {
		t.Error("CONNECT: ", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Error("CONNECT: ", err)
	} else if resp.StatusCode != 200 {
		t.Error("CONNECT failed, status code: ", resp.StatusCode)
	}

	config, err := websocket.NewConfig("ws://"+wsaddr, "http://localhost")
	if err != nil {
		t.Error("Creating websocket config: ", err)
	}
	ws, err := websocket.NewClient(config, io.ReadWriteCloser(conn))
	if err != nil {
		t.Error("Creating websocket client: ", err)
	}

	hello := "Hello world!\n"
	if _, err := ws.Write([]byte(hello)); err != nil {
		t.Error("Sending websocket message: ", err)
	}
	reply := make([]byte, 512)
	var n int
	if n, err = ws.Read(reply); err != nil {
		t.Error("Receiving websocket message: ", err)
	}

	if n != len(hello) || string(reply[:n]) != hello {
		t.Error("Received invalid websocket reply: ", reply)
	}
}

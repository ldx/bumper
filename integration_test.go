package main

import (
	"crypto/tls"
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

func createConfig(certfile string, keyfile string) (bumper *BumperProxy,
	err error) {
	bumper = new(BumperProxy)

	// Sensible defaults.
	bumper.proxy = ""
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

func proxyViaBumper(t *testing.T, listener net.Listener, url string) *http.Response {
	go func() {
		http.Serve(listener, http.HandlerFunc(handler))
	}()

	bumpersrv, err := net.Listen("tcp", "localhost:12346")
	if err != nil {
		t.Error("Listen: ", err)
	}
	defer bumpersrv.Close()

	go func() {
		conn, err := bumpersrv.Accept()
		if err != nil {
			t.Error("Accept: ", err)
		}

		bumper, err := createConfig("cybervillains.crt", "cybervillains.key")
		if err != nil {
			t.Error("createConfig: ", err)
		}

		handleClient(conn, bumper)
	}()

	tr, err := newTransport("localhost:12346", true)
	if err != nil {
		t.Error("newTransport: ", err)
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		t.Error("RoundTrip: ", err)
	}
	if resp.StatusCode != 200 {
		t.Error("RoundTrip failed, response: ", resp)
	}

	return resp
}

func TestHttp(t *testing.T) {
	log.SetOutput(noLog{})

	hostport := "localhost:12345"

	listener, err := net.Listen("tcp", hostport)
	if err != nil {
		t.Error("Listen: ", err)
	}
	defer listener.Close()

	proxyViaBumper(t, listener, "http://"+hostport)
}

func TestHttps(t *testing.T) {
	log.SetOutput(noLog{})

	hostport := "localhost:12345"

	plainlistener, err := net.Listen("tcp", hostport)
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

	resp := proxyViaBumper(t, listener, "https://"+hostport)
	issuer := resp.TLS.PeerCertificates[0].Issuer
	if issuer.Country[0] != "US" ||
		issuer.Organization[0] != "CyberVillians.com" ||
		issuer.OrganizationalUnit[0] != "CyberVillians Certification Authority" {
		t.Error("Invalid issuer in peer certificate: ", issuer)
	}
}

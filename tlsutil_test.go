package main

import (
    "bufio"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "os"
    "sync"
    "testing"
)

type noLog struct{}

func (noLog) Write(p []byte) (int, error) {
    return len(p), nil
}

func TestStartTls(t *testing.T) {
    log.SetOutput(noLog{})

    tmp, err := ioutil.TempDir("", "bumper")
    if err != nil {
        t.Error(err)
    }
    defer os.RemoveAll(tmp)

    bumper, err := newBumper(tmp)
    if err != nil {
        t.Error(err)
    }

    host := "127.0.0.1"

    createCerts(bumper, []string{host})
    cert, ok := bumper.certs[host]
    if !ok {
        t.Error("Failed to create certificate for " + host)
    }

    addr := host + ":9236"
    srv, err := net.Listen("tcp", addr)
    if err != nil {
        t.Error(fmt.Sprintf("Can't start listener on %s: %s\n", addr, err))
        os.Exit(1)
    }

    go func() {
        conn, err := srv.Accept()
        if err != nil {
            t.Error(fmt.Sprintf("Accepting client: %s\n", err))
        }
        tlsconn, err := StartTls(conn, cert)

        reader := bufio.NewReader(tlsconn)
        writer := io.Writer(tlsconn)

        req, err := http.ReadRequest(reader)
        if err != nil {
            t.Error(fmt.Sprintf("Reading request: %s\n", err))
        }

        if req.Method != "GET" {
            t.Error(fmt.Sprintf("Invalid request method: %s\n", req.Method))
        }

        writer.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
        tlsconn.Close()
        conn.Close()
    }()

    pool := x509.NewCertPool()
    pool.AddCert(bumper.cacert.Leaf)

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs: pool,
        },
    }

    client := http.Client{Transport: tr}
    resp, err := client.Get("https://" + addr)
    if err != nil {
        t.Error(err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        t.Error(fmt.Sprintf("Reading HTTP body from response: %s\n", err))
    }
    if len(body) > 0 {
        t.Error(fmt.Sprintf("Invalid HTTP body in response: %s\n", body))
    }
}

func TestReadCertificates(t *testing.T) {
    log.SetOutput(noLog{})

    tmp, err := ioutil.TempDir("", "bumper")
    if err != nil {
        t.Error(err)
    }
    defer os.RemoveAll(tmp)

    bumper, err := newBumper(tmp)
    if err != nil {
        t.Error(err)
    }

    names := []string{"localhost", "google.com", "asdfasdf.com"}

    createCerts(bumper, names)

    if len(bumper.certs) != len(names) {
        t.Error(fmt.Sprintf("Failed to create certificates, %d != %d",
            len(bumper.certs), len(names)))
    }

    cacert, err := ReadCert("./cybervillains.crt", "./cybervillains.key")
    if err != nil {
        t.Error(err)
    }
    certs := make(map[string]*tls.Certificate)
    var maxserial int64
    err = ReadCertificates(tmp, cacert, certs, &maxserial)
    for _, name := range names {
        cert, ok := certs[name]
        if !ok {
            t.Error(
                fmt.Sprintf("Can't find certificate for %s in map\n", name))
        }

        cn := cert.Leaf.Subject.CommonName
        if cn != name {
            t.Error(fmt.Sprintf("Invalid CN '%s' for %s in map\n", cn, name))
        }

        pool := x509.NewCertPool()
        pool.AddCert(cacert.Leaf)
        _, err := cert.Leaf.Verify(x509.VerifyOptions{
            DNSName: name,
            Roots:   pool,
        })
        if err != nil {
            t.Error(fmt.Sprintf("Invalid certificate created for %s: %s\n",
                name, err))
        }
    }

    if maxserial > 3 {
        t.Error("Unexpected max serial number " + string(maxserial))
    }
}

func TestReadCert(t *testing.T) {
    log.SetOutput(noLog{})

    _, err := ReadCert("./cybervillains.crt", "./cybervillains.key")
    if err != nil {
        t.Error(err)
    }
}

func createCerts(bumper *BumperProxy, names []string) (err error) {
    for _, name := range names {
        if _, err = GetCertificate(name, bumper); err != nil {
            return err
        }
    }

    return nil
}

func newBumper(certdir string) (bumper *BumperProxy, err error) {
    cacert, err := ReadCert("./cybervillains.crt", "./cybervillains.key")
    if err != nil {
        return nil, err
    }

    bp := BumperProxy{
        certs:   make(map[string]*tls.Certificate),
        cacert:  *cacert,
        certdir: certdir,
        mutex:   new(sync.RWMutex),
    }

    return &bp, nil
}

func TestGetCertificate(t *testing.T) {
    log.SetOutput(noLog{})

    tmp, err := ioutil.TempDir("", "bumper")
    if err != nil {
        t.Error(err)
    }
    defer os.RemoveAll(tmp)

    bumper, err := newBumper(tmp)
    if err != nil {
        t.Error(err)
    }

    names := []string{"localhost", "google.com", "asdfasdf.com"}

    createCerts(bumper, names)

    if len(bumper.certs) != len(names) {
        t.Error(fmt.Sprintf("Failed to create certificates, %d != %d",
            len(bumper.certs), len(names)))
    }
}

package main

import (
    "bufio"
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"
    "fmt"
    "github.com/jessevdk/go-flags"
    "io"
    "io/ioutil"
    "log"
    "math/big"
    "net"
    "net/http"
    "net/url"
    "os"
    "strings"
    "time"
)

//
// Global variables.
//
var logger *log.Logger

//
// This holds all the certificate information for Bumper.
//
type BumperProxy struct {
    cacert  tls.Certificate
    certs   map[string]*tls.Certificate
    certdir string
}

type lengthFixReadCloser struct {
    io.Reader
    io.Closer
}

//
// Main listener loop.
//
func Loop(addr string, bumper *BumperProxy) {
    logger.Printf("Starting listener on %s\n", addr)

    srv, err := net.Listen("tcp", addr)
    if err != nil {
        logger.Printf("Can't start listener on %s: %s\n", addr, err)
        os.Exit(1)
    }

    for {
        conn, err := srv.Accept()
        if err != nil {
            logger.Printf("Warning: accepting client: %s\n", err)
            continue
        }

        go HandleClient(conn, bumper)
    }
}

func FixRequest(req *http.Request, orig_uri string) (err error) {
    if orig_uri != "" {
        uri, err := url.Parse("https://" + orig_uri + req.RequestURI)
        if err != nil {
            return err
        }

        req.URL = uri
        req.RequestURI = ""
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

//
// Goroutine handling a client, proxying requests and responses.
//
func HandleClient(conn net.Conn, bumper *BumperProxy) {
    defer conn.Close()

    cli := conn.RemoteAddr()

    reader := bufio.NewReader(conn)
    writer := io.Writer(conn)

    tr := &http.Transport{}

    orig_uri := ""
    for {
        req, err := http.ReadRequest(reader)
        if err == io.EOF {
            logger.Printf("(%s) client closed connection\n", cli)
            return
        } else if err != nil {
            logger.Printf("(%s) error reading request: %s\n", cli, err)
            return
        }

        logger.Printf("(%s) -> %s %s\n", cli, req.Method, req.RequestURI)
        //req.Write(os.Stdout)

        proto := req.Proto

        if req.Method == "CONNECT" {
            if !strings.Contains(req.Host, ":") {
                writer.Write([]byte(fmt.Sprintf(
                    "%s 400 Invalid Request\r\n\r\n", proto)))
                return
            }
            host := strings.Split(req.Host, ":")[0]

            // Retrieve or create fake certificate for 'host'.
            cert, err := GetCertificate(host, &bumper.cacert, bumper.certs,
                bumper.certdir)
            if err != nil {
                logger.Printf("(%s) error getting new cert: %s\n", cli, err)
                return
            }

            // Okay, we are ready to start TLS.
            writer.Write([]byte(fmt.Sprintf("%s 200 OK\r\n\r\n", proto)))
            logger.Printf("(%s) <- 200 %s\n", cli, req.RequestURI)

            tlsconn, err := StartTls(conn, cert)
            if err != nil {
                logger.Printf("(%s) error starting TLS: %s\n", cli, err)
                return
            }
            defer tlsconn.Close()

            reader = bufio.NewReader(tlsconn)
            writer = io.Writer(tlsconn)

            orig_uri = req.RequestURI

            continue
        }

        if FixRequest(req, orig_uri) != nil {
            logger.Printf("(%s) invalid request URI %s\n", cli,
                req.RequestURI)
            return
        }

        resp, err := tr.RoundTrip(req)
        if err != nil {
            logger.Printf("(%s) error proxying %s: %s\n", cli, req, err)
            writer.Write([]byte(fmt.Sprintf(
                "%s 400 Bad Request %s\r\n\r\n", proto, err)))
            return
        }

        if FixResponse(resp) != nil {
            logger.Printf("(%s) error fixing Content-Lenght for %s: %s\n",
                cli, req, err)
            writer.Write([]byte(fmt.Sprintf(
                "%s 500 Internal Server Error %s\r\n\r\n", proto, err)))
            return
        }

        resp.Write(writer)

        logger.Printf("(%s) <- %s %s\n", cli, resp.Status, req.URL)
        //resp.Write(os.Stdout)

        if req.Close || resp.Close {
            logger.Printf("(%s) closing connection\n", cli)
            return
        }
    }
}

func StartTls(conn net.Conn, cert *tls.Certificate) (tlsconn *tls.Conn,
    err error) {
    config := &tls.Config{
        NextProtos:   []string{"HTTP/1.1"},
        Certificates: []tls.Certificate{*cert},
    }

    tlsconn = tls.Server(conn, config)
    tlsconn.Handshake()

    return tlsconn, nil
}

func GetCertificate(
    name string,
    cacert *tls.Certificate,
    certs map[string]*tls.Certificate,
    certdir string) (cert *tls.Certificate, err error) {
    // Check if we have the certificate for the server in our map.
    if cert, ok := certs[name]; ok {
        // Verify certificate to make sure it is still valid.
        pool := x509.NewCertPool()
        pool.AddCert(cacert.Leaf)
        _, err = cert.Leaf.Verify(x509.VerifyOptions{
            DNSName: name,
            Roots:   pool,
        })
        if err == nil {
            return cert, nil
        }
    }

    // We have to create the certificate.
    key, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        return nil, errors.New("Certificate generation failed")
    }
    privkey := x509.MarshalPKCS1PrivateKey(key)

    dercert, err := x509.CreateCertificate(
        rand.Reader,
        &x509.Certificate{
            Subject: pkix.Name{
                CommonName:   name,
                Organization: []string{"Bumper Proxy LLC"},
            },
            KeyUsage: (x509.KeyUsageDigitalSignature |
                x509.KeyUsageKeyEncipherment),
            SerialNumber: big.NewInt(1),
            NotAfter:     time.Now().AddDate(10, 0, 0).UTC(),
            NotBefore:    time.Now().AddDate(-10, 0, 0).UTC(),
        },
        cacert.Leaf,
        &key.PublicKey,
        cacert.PrivateKey)
    if err != nil {
        return nil, errors.New("Certificate generation failed")
    }

    certblock := &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: dercert,
    }
    keyblock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privkey,
    }

    pemcert := pem.EncodeToMemory(certblock)
    pemkey := pem.EncodeToMemory(keyblock)

    crt, err := tls.X509KeyPair(pemcert, pemkey)
    if err != nil {
        return nil, errors.New("Certificate generation failed")
    }
    cert = &crt

    path := fmt.Sprintf("%s%c%s.crt", certdir, os.PathSeparator, name)
    certfile, err := os.Create(path)
    if err != nil {
        return nil, errors.New(
            fmt.Sprintf("Failed to save certificate as %s", path))
    }
    pem.Encode(certfile, &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: dercert})
    certfile.Close()

    path = fmt.Sprintf("%s%c%s.key", certdir, os.PathSeparator, name)
    keyfile, err := os.Create(path)
    if err != nil {
        return nil, errors.New(
            fmt.Sprintf("Failed to save private key as %s", path))
    }
    pem.Encode(keyfile, &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privkey,
    })
    keyfile.Close()

    logger.Printf("Created certificate for %s\n", name)

    certs[name] = cert
    return cert, nil
}

func ReadCertificates(dir string,
    certs map[string]*tls.Certificate) (err error) {
    // Open directory. If it does not exist, try to create it.
    directory, err := os.Open(dir)
    if err != nil {
        err = os.Mkdir(dir, 0755)
        if err != nil {
            logger.Printf("Error opening certificate directory %s: %s\n", dir,
                err)
            return err
        }

        directory, err = os.Open(dir)
        if err != nil {
            logger.Printf("Error opening certificate directory %s: %s\n", dir,
                err)
            return err
        }
    }
    defer directory.Close()

    files, err := directory.Readdir(0)
    if err != nil {
        logger.Printf("Error opening certificate directory %s: %s\n", dir, err)
        return err
    }

    // Loop through the directory, trying to read in every certificate/key.
    // Certificate filenames must have the ".crt" suffix, and their
    // corresponding private key must have the ".key" suffix. Subdirectories
    // are not traversed.
    for i := range files {
        file := files[i]
        if file.IsDir() || !strings.HasSuffix(file.Name(), ".crt") {
            continue
        }

        certpath := fmt.Sprintf("%s%c%s", dir, os.PathSeparator, file.Name())
        keypath := fmt.Sprintf("%s%c%s", dir, os.PathSeparator,
            strings.TrimSuffix(file.Name(), ".crt")+".key")

        cert, err := ReadCert(certpath, keypath)
        if err != nil {
            logger.Printf("Skipping %s: can't parse certificate\n", file.Name())
            continue
        }
        leaf := cert.Leaf

        if leaf.DNSNames != nil {
            for j := range leaf.DNSNames {
                logger.Printf("Found certificate for %s\n", leaf.DNSNames[j])
                certs[leaf.DNSNames[j]] = cert
            }
        } else if leaf.RawSubject != nil {
            logger.Printf("Found certificate for %s\n",
                leaf.Subject.CommonName)
            certs[string(leaf.Subject.CommonName)] = cert
        }
    }

    return nil
}

func ReadCert(certpath, keypath string) (cert *tls.Certificate,
    err error) {
    crt, err := tls.LoadX509KeyPair(certpath, keypath)
    if err != nil {
        return nil, errors.New(fmt.Sprintf(
            "Error loading certificate from %s; %s", certpath, keypath))
    }

    leaf, err := x509.ParseCertificate(crt.Certificate[0])
    if err != nil {
        return nil, errors.New(fmt.Sprintf(
            "Error parsing certificate from %s; %s", certpath, keypath))
    }
    crt.Leaf = leaf

    return &crt, nil
}

//
// Command line options.
//
var opts struct {
    CertDir string `short:"d" long:"certdir" value-name:"<directory>" description:"Directory where generated certificates are stored." required:"true"`
    CaCert  string `short:"c" long:"cacert" value-name:"<file>" description:"CA certificate file." required:"true"`
    CaKey   string `short:"k" long:"cakey" value-name:"<file>" description:"CA private key file." required:"true"`
    Listen  string `short:"l" long:"listen" value-name:"<host:port>" description:"Host and port where Bumperproxy will be listening." default:"localhost:9718"`
    Verbose []bool `short:"v" long:"verbose" description:"Enable verbose debugging."`
}

func main() {
    args, err := flags.Parse(&opts)
    if err != nil {
        if len(args) == 1 && args[0] == "--help" {
            os.Exit(0)
        } else {
            os.Exit(1)
        }
    }

    logger = log.New(os.Stdout, "[bumper] ", 0)

    bumper := new(BumperProxy)

    // Load CA certificate and key.
    cacert, err := ReadCert(opts.CaCert, opts.CaKey)
    if err != nil {
        logger.Printf("%s\n", err)
        os.Exit(1)
    }
    bumper.cacert = *cacert

    // Load server certificates.
    bumper.certdir = opts.CertDir

    bumper.certs = make(map[string]*tls.Certificate)
    err = ReadCertificates(opts.CertDir, bumper.certs)
    if err != nil {
        logger.Printf("Error loading certificates from '%s': %s\n", opts.CertDir,
            err)
        os.Exit(1)
    }

    Loop(opts.Listen, bumper)
}

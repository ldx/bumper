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
    "sync"
    "time"
)

//
// This holds all the certificate information for Bumper.
//
type BumperProxy struct {
    cacert     tls.Certificate
    certs      map[string]*tls.Certificate
    mutex      *sync.RWMutex
    certdir    string
    maxserial  int64
    proxy      string
    skipverify bool
    addorig    bool
}

type lengthFixReadCloser struct {
    io.Reader
    io.Closer
}

//
// Main listener loop.
//
func Loop(addr string, bumper *BumperProxy) {
    log.Printf("Starting listener on %s\n", addr)

    srv, err := net.Listen("tcp", addr)
    if err != nil {
        log.Printf("Can't start listener on %s: %s\n", addr, err)
        os.Exit(1)
    }

    for {
        conn, err := srv.Accept()
        if err != nil {
            log.Printf("Warning: accepting client: %s\n", err)
            continue
        }

        go HandleClient(conn, bumper)
    }
}

func FixRequest(req *http.Request, orig_uri string, addhdr bool) (err error) {
    if orig_uri != "" {
        uri, err := url.Parse("https://" + orig_uri + req.RequestURI)
        if err != nil {
            return err
        }

        req.URL = uri
        req.RequestURI = ""
    }

    req.Header.Set("X-Orig-Uri", req.URL.String())

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

//
// Goroutine handling a client, proxying requests and responses.
//
func HandleClient(conn net.Conn, bumper *BumperProxy) {
    defer conn.Close()

    var proxy func(*http.Request) (*url.URL, error) = nil
    if bumper.proxy != "" {
        proxyurl, err := url.Parse("http://" + bumper.proxy)
        if err != nil {
            log.Printf("Setting parent proxy to %s: %s\n",
                bumper.proxy, err)
            return
        }
        proxy = http.ProxyURL(proxyurl)
    }

    tr := &http.Transport{
        Proxy: proxy,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: bumper.skipverify,
        },
    }

    cli := conn.RemoteAddr().String()

    reader := bufio.NewReader(conn)
    writer := io.Writer(conn)

    orig_uri := ""
    for {
        req, err := http.ReadRequest(reader)
        if err == io.EOF {
            log.Printf("(%s) client closed connection\n", cli)
            return
        } else if err != nil {
            log.Printf("(%s) error reading request: %s\n", cli, err)
            return
        }

        log.Printf("(%s) -> %s %s\n", cli, req.Method, req.RequestURI)
        //req.Write(os.Stdout)

        if req.Method == "CONNECT" {
            if !strings.Contains(req.Host, ":") {
                SendResp(cli, writer, 400,
                    fmt.Sprintf("invalid host '%s'", req.Host), false)
                return
            }
            host := strings.Split(req.Host, ":")[0]

            // Retrieve or create fake certificate for 'host'.
            cert, err := GetCertificate(host, bumper)
            if err != nil {
                log.Printf("(%s) error getting new cert: %s\n", cli, err)
                SendResp(cli, writer, 500, err.Error(), false)
                return
            }

            // Okay, we are ready to start TLS.
            SendResp(cli, writer, 200, "", true)

            tlsconn, err := StartTls(conn, cert)
            if err != nil {
                log.Printf("(%s) error starting TLS: %s\n", cli, err)
                return
            }
            defer tlsconn.Close()

            reader = bufio.NewReader(tlsconn)
            writer = io.Writer(tlsconn)

            orig_uri = req.RequestURI

            continue
        }

        if FixRequest(req, orig_uri, bumper.addorig) != nil {
            log.Printf("(%s) invalid request URI %s\n", cli,
                req.RequestURI)
            return
        }

        resp, err := tr.RoundTrip(req)
        if err != nil {
            statuscode := 502
            if resp != nil {
                statuscode = resp.StatusCode
            }
            SendResp(cli, writer, statuscode, err.Error(), false)
            return
        }

        if FixResponse(resp) != nil {
            log.Printf("(%s) error fixing Content-Lenght for %s: %s\n",
                cli, req, err)
            SendResp(cli, writer, 500, err.Error(), false)
            return
        }

        resp.Write(writer)

        log.Printf("(%s) <- %s %s\n", cli, resp.Status, req.URL)
        //resp.Write(os.Stdout)

        if req.Close || resp.Close {
            log.Printf("(%s) closing connection\n", cli)
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

func GetCertificate(name string, bumper *BumperProxy) (cert *tls.Certificate,
    err error) {
    // Check if we have the certificate for the server in our map.
    bumper.mutex.RLock()
    cert, ok := bumper.certs[name]
    bumper.mutex.RUnlock()
    if ok {
        return cert, nil
    }

    // We have to create the certificate.
    key, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        return nil, errors.New("Certificate generation failed")
    }
    privkey := x509.MarshalPKCS1PrivateKey(key)

    bumper.mutex.Lock()
    bumper.maxserial++
    serial := bumper.maxserial
    bumper.mutex.Unlock()

    dercert, err := x509.CreateCertificate(
        rand.Reader,
        &x509.Certificate{
            Subject: pkix.Name{
                CommonName:   name,
                Organization: []string{"Bumper Proxy LLC"},
            },
            KeyUsage: (x509.KeyUsageDigitalSignature |
                x509.KeyUsageKeyEncipherment),
            SerialNumber: big.NewInt(serial),
            NotAfter:     time.Now().AddDate(10, 0, 0).UTC(),
            NotBefore:    time.Now().AddDate(-10, 0, 0).UTC(),
        },
        bumper.cacert.Leaf,
        &key.PublicKey,
        bumper.cacert.PrivateKey)
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

    path := fmt.Sprintf("%s%c%s.crt", bumper.certdir, os.PathSeparator, name)
    certfile, err := os.Create(path)
    if err != nil {
        return nil, errors.New(
            fmt.Sprintf("Failed to save certificate as %s", path))
    }
    pem.Encode(certfile, &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: dercert})
    certfile.Close()

    path = fmt.Sprintf("%s%c%s.key", bumper.certdir, os.PathSeparator, name)
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

    log.Printf("Created certificate for %s\n", name)

    bumper.mutex.Lock()
    bumper.certs[name] = cert
    bumper.mutex.Unlock()

    return cert, nil
}

func IsCertificateValid(ca, cert *tls.Certificate, name string) (valid bool) {
    // Make sure certificate is still valid.
    pool := x509.NewCertPool()
    pool.AddCert(ca.Leaf)

    _, err := cert.Leaf.Verify(x509.VerifyOptions{
        DNSName: name,
        Roots:   pool,
    })

    if err == nil {
        return true
    } else {
        return false
    }
}

func ReadCertificates(dir string,
    cacert *tls.Certificate,
    certs map[string]*tls.Certificate,
    maxserial *int64) (err error) {
    // Open directory. If it does not exist, try to create it.
    directory, err := os.Open(dir)
    if err != nil {
        err = os.Mkdir(dir, 0755)
        if err != nil {
            log.Printf("Error opening certificate directory %s: %s\n", dir,
                err)
            return err
        }

        directory, err = os.Open(dir)
        if err != nil {
            log.Printf("Error opening certificate directory %s: %s\n", dir,
                err)
            return err
        }
    }
    defer directory.Close()

    *maxserial = 1 // 1 is the CA certificate

    files, err := directory.Readdir(0)
    if err != nil {
        log.Printf("Error opening certificate directory %s: %s\n", dir, err)
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
            log.Printf("Skipping %s: can't parse cert\n", file.Name())
            continue
        }
        leaf := cert.Leaf

        if leaf.DNSNames != nil {
            for _, name := range leaf.DNSNames {
                if !IsCertificateValid(cacert, cert, name) {
                    log.Printf("Invalid cert for %s, removing\n", name)
                    os.Remove(certpath)
                    os.Remove(keypath)
                    continue
                }

                log.Printf("Found certificate for %s (#%d)\n", name,
                    leaf.Subject.CommonName, leaf.SerialNumber)
                certs[name] = cert
                if leaf.SerialNumber.Int64() > *maxserial {
                    *maxserial = leaf.SerialNumber.Int64()
                }
            }
        } else if leaf.Subject.CommonName != "" {
            log.Printf("Found certificate for %s (#%d)\n",
                leaf.Subject.CommonName, leaf.SerialNumber)
            certs[string(leaf.Subject.CommonName)] = cert
            if leaf.SerialNumber.Int64() > *maxserial {
                *maxserial = leaf.SerialNumber.Int64()
            }
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
    CertDir     string `short:"d" long:"certdir" value-name:"<directory>" description:"Directory where generated certificates are stored." required:"true"`
    CaCert      string `short:"c" long:"cacert" value-name:"<file>" description:"CA certificate file." required:"true"`
    CaKey       string `short:"k" long:"cakey" value-name:"<file>" description:"CA private key file." required:"true"`
    Proxy       string `short:"p" long:"proxy" value-name:"<host:port>" description:"HTTP parent proxy to use for all requests (both HTTP and HTTPS)."`
    SkipVerify  bool   `short:"n" long:"skipverify" description:"If set, BumperProxy will not verify the certificate of HTTPS websites." default:"false"`
    Listen      string `short:"l" long:"listen" value-name:"<host:port>" description:"Host and port where Bumperproxy will be listening." default:"localhost:9718"`
    AddXOrigUri bool   `short:"x" long:"addxoriguri" description:"If set, BumperProxy will add an X-Orig-Uri header with the original URI to requests." default:"false"`
    Verbose     []bool `short:"v" long:"verbose" description:"Enable verbose debugging."`
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

    log.SetOutput(os.Stdout)
    log.SetPrefix("[bumper] ")

    bumper := new(BumperProxy)

    bumper.proxy = opts.Proxy
    bumper.addorig = opts.AddXOrigUri
    bumper.skipverify = opts.SkipVerify

    // Load CA certificate and key.
    cacert, err := ReadCert(opts.CaCert, opts.CaKey)
    if err != nil {
        log.Printf("%s\n", err)
        os.Exit(1)
    }
    bumper.cacert = *cacert

    // Load server certificates.
    bumper.certdir = opts.CertDir

    bumper.certs = make(map[string]*tls.Certificate)
    err = ReadCertificates(bumper.certdir, &bumper.cacert, bumper.certs,
        &bumper.maxserial)
    if err != nil {
        log.Printf("Error loading certificates from '%s': %s\n", opts.CertDir,
            err)
        os.Exit(1)
    }

    bumper.mutex = new(sync.RWMutex)

    Loop(opts.Listen, bumper)
}

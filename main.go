package main

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "github.com/jessevdk/go-flags"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
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

    //log.SetOutput(os.Stdout)
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

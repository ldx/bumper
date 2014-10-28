package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io"
	"io/ioutil"
	"log"
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
	timeout    int64
	proxy      string
	skipverify bool
	addorig    bool
}

type Proxy struct {
	proxy     string
	conn      net.Conn
	reader    *bufio.Reader
	writer    io.Writer
	isconnect bool
}

//
// Main listener loop.
//
func loop(addr string, bumper *BumperProxy) {
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

		go handleClient(conn, bumper)
	}
}

func doStream(r *bufio.Reader, w io.Writer) <-chan error {
	errCh := make(chan (error))

	go func() {
		for {
			buf := make([]byte, 8192)
			n, err := r.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	return errCh
}

//
// Connect to other side and stream all data sent/received.
//
func streamData(cli string,
	clireader *bufio.Reader, cliwriter io.Writer,
	srvreader *bufio.Reader, srvwriter io.Writer) {
	c2sch := doStream(clireader, srvwriter)
	s2cch := doStream(srvreader, cliwriter)

	log.Printf("(%s) streaming data\n", cli)

	select {
	case err1 := <-c2sch:
		log.Printf("(%s) -> %s", cli, err1)
	case err2 := <-s2cch:
		log.Printf("(%s) <- %s", cli, err2)
	}
}

//
// Connect to 'host' and stream all data sent/received.
//
func streamDataToServer(cli string, clireader *bufio.Reader,
	cliwriter io.Writer, host string) {
	if host == "" {
		log.Printf("(%s) error, missing host header\n", cli)
		return
	}

	conn, err := net.Dial("tcp", host)
	if conn == nil {
		log.Printf("(%s) error connecting to '%s': %s\n", cli, host, err)
		return
	}

	r := bufio.NewReader(conn)
	w := io.Writer(conn)

	streamData(cli, clireader, cliwriter, r, w)
}

//
// Connect to parent proxy.
//
func connectToProxy(cli string, proxy *Proxy) error {
	var err error
	proxy.conn, err = net.Dial("tcp", proxy.proxy)
	if err != nil {
		log.Printf("(%s) error connecting to parent proxy '%s': %s\n",
			cli, proxy.proxy, err)
		return err
	}
	log.Printf("(%s) connected to parent proxy, %s<->%s\n",
		cli, proxy.conn.LocalAddr(), proxy.proxy)

	proxy.reader = bufio.NewReader(proxy.conn)
	proxy.writer = io.Writer(proxy.conn)

	return nil
}

func proxyRoundTrip(cli string, req *http.Request,
	proxy *Proxy) (*http.Response, error) {
	log.Printf("(%s) request: %s %s\n", cli, req.RequestURI, req.Header)

	// Save the body in case we need to reconnect.
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	b := make([]byte, len(body))
	copy(b, body)
	req.Body = ioutil.NopCloser(bytes.NewReader(b))

	if proxy.isconnect {
		if err := req.Write(proxy.writer); err != nil {
			return nil, err
		}
	} else {
		if err := req.WriteProxy(proxy.writer); err != nil {
			return nil, err
		}
	}

	resp, err := http.ReadResponse(proxy.reader, req)
	if err == io.ErrUnexpectedEOF && !proxy.isconnect {
		// Try once more.
		log.Printf("(%s) proxy connection has been closed, retrying\n", cli)
		proxy.conn.Close()
		err = connectToProxy(cli, proxy)
		if err != nil {
			return nil, err
		}

		b = make([]byte, len(body))
		copy(b, body)
		req.Body = ioutil.NopCloser(bytes.NewReader(b))
		if err = req.WriteProxy(proxy.writer); err != nil {
			return nil, err
		}
		resp, err = http.ReadResponse(proxy.reader, req)
	}

	return resp, err
}

func newTransport(proxy string, skipverify bool) (*http.Transport, error) {
	var proxyurl func(*http.Request) (*url.URL, error) = nil
	if proxy != "" {
		url, err := url.Parse("http://" + proxy)
		if err != nil {
			log.Printf("Error setting parent proxy to %s: %s\n",
				proxy, err)
			return nil, err
		}
		proxyurl = http.ProxyURL(url)
	}

	tr := &http.Transport{
		Proxy: proxyurl,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipverify,
		},
	}

	return tr, nil
}

//
// Goroutine handling a client, proxying requests and responses.
//
func handleClient(origconn net.Conn, bumper *BumperProxy) {
	conn := newBufferedConn(origconn)
	defer conn.Close()

	cli := conn.RemoteAddr().String()
	log.Printf("(%s) client connected\n", cli)

	tr, err := newTransport(bumper.proxy, bumper.skipverify)
	if err != nil {
		return
	}

	clireader := bufio.NewReader(conn)
	cliwriter := io.Writer(conn)

	var proxy *Proxy
	if bumper.proxy != "" {
		proxy = &Proxy{}
		proxy.proxy = bumper.proxy
		err = connectToProxy(cli, proxy)
		if err != nil {
			SendResp(cli, cliwriter, 502,
				fmt.Sprintf("error connecting to parent proxy '%s': %s",
					bumper.proxy, err), false)
			return
		}
		defer proxy.conn.Close()
	}

	orig_uri := ""
	for {
		// Idle connections are closed after bumper.timeout seconds.
		conn.SetReadDeadline(
			time.Now().Add(time.Duration(bumper.timeout) * time.Second))

		req, err := http.ReadRequest(clireader)
		if err == io.EOF {
			log.Printf("(%s) client closed connection\n", cli)
			return
		} else if err != nil {
			log.Printf("(%s) error reading request: %s\n", cli, err)
			return
		}

		log.Printf("(%s) -> %s %s\n", cli, req.Method, req.RequestURI)

		if req.Method == "CONNECT" {
			if !strings.Contains(req.Host, ":") {
				SendResp(cli, cliwriter, 400,
					fmt.Sprintf("invalid host '%s'", req.Host), false)
				return
			}
			host := strings.Split(req.Host, ":")[0]

			// Retrieve or create fake certificate for 'host'.
			cert, err := GetCertificate(host, bumper)
			if err != nil {
				log.Printf("(%s) error getting new cert: %s\n", cli, err)
				SendResp(cli, cliwriter, 500, err.Error(), false)
				return
			}

			// Okay, we are ready to start TLS.
			SendResp(cli, cliwriter, 200, "", true)

			tlsconn, err := StartTls(conn, cert)
			if err != nil {
				log.Printf("(%s) failed to start TLS: %s\n", cli, err)
				return
			} else if tlsconn == nil {
				// This is not SSL/TLS. Start streaming.
				log.Printf("(%s) streaming connection\n", cli)
				if proxy != nil {
					// Send CONNECT to parent proxy.
					resp, err := proxyRoundTrip(cli, req, proxy)
					if err != nil {
						log.Printf("(%s) failed to CONNECT via parent: %s\n",
							cli, err)
					} else if resp.StatusCode != 200 {
						log.Printf("(%s) failed to CONNECT via parent: %d\n",
							cli, resp.StatusCode)
					} else {
						conn.SetReadDeadline(time.Time{})
						streamData(cli, clireader, cliwriter, proxy.reader,
							proxy.writer)
					}
					return
				} else {
					// Direct connection to server.
					conn.SetReadDeadline(time.Time{})
					streamDataToServer(cli, clireader, cliwriter, req.Host)
					return
				}
			} else {
				orig_uri = req.RequestURI
				if strings.HasSuffix(orig_uri, ":443") {
					orig_uri = orig_uri[:len(orig_uri)-4]
				}
				defer tlsconn.Close()
				clireader = bufio.NewReader(tlsconn)
				cliwriter = io.Writer(tlsconn)

				continue
			}
		}

		if FixRequest(req, orig_uri, bumper.addorig) != nil {
			log.Printf("(%s) invalid request URI %s\n", cli, req.RequestURI)
			return
		}

		var resp *http.Response
		if proxy != nil {
			resp, err = proxyRoundTrip(cli, req, proxy)
		} else {
			resp, err = tr.RoundTrip(req)
		}
		if err != nil {
			log.Printf("(%s) error reading response: %s\n", cli, err)
			var statuscode int
			if resp != nil {
				log.Printf("(%s) response was: %s\n", cli, resp)
				statuscode = resp.StatusCode
			} else {
				statuscode = 502
			}
			SendResp(cli, cliwriter, statuscode, err.Error(), false)
			return
		}

		if FixResponse(resp) != nil {
			log.Printf("(%s) error fixing Content-Lenght for %s: %s\n",
				cli, req, err)
			SendResp(cli, cliwriter, 500, err.Error(), false)
			return
		}

		log.Printf("(%s) <- %s %s\n", cli, resp.Status, req.URL)
		resp.Write(cliwriter)
		resp.Body.Close()

		if req.Close || resp.Close {
			log.Printf("(%s) closing connection\n", cli)
			return
		} else if resp.StatusCode == 101 {
			// Upgrade connection, probably websocket.
			if proxy != nil {
				conn.SetReadDeadline(time.Time{})
				streamData(cli, clireader, cliwriter, proxy.reader,
					proxy.writer)
			} else {
				// XXX: make this work for direct connections. However, we
				// need the underlying net.Conn of the transport for
				// streaming.
			}
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
	Timeout     int64  `short:"t" long:"timeout" value-name:"<seconds>" description:"Timeout for client connections." default:"120"`
	AddXOrigUri bool   `short:"x" long:"addxoriguri" description:"If set, BumperProxy will add an X-Orig-Uri header with the original URI to requests." default:"false"`
	Verbose     []bool `short:"v" long:"verbose" description:"Enable verbose debugging."`
	Version     bool   `short:"V" long:"version" description:"Show version."`
}

var version string

func main() {
	args, err := flags.Parse(&opts)
	if opts.Version {
		if version == "" {
			version = "unknown"
		}
		fmt.Printf("Bumper version %s\n", version)
	}
	if err != nil {
		fmt.Printf("Error %s\n", err)
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
	bumper.timeout = opts.Timeout

	// Load CA certificate and key.
	cacert, err := ReadCert(opts.CaCert, opts.CaKey)
	if err != nil {
		log.Printf("%s\n", err)
		os.Exit(1)
	}
	bumper.cacert = *cacert

	// First serial is the CA's.
	bumper.maxserial = bumper.cacert.Leaf.SerialNumber.Int64()

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

	loop(opts.Listen, bumper)
}

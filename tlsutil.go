package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func isHandshake(reader *bufio.Reader) (bool, error) {
	buf, err := reader.Peek(9)
	if err != nil {
		log.Printf("failed to peek into CONNECT stream: %s\n", err)
		return false, err
	}
	if len(buf) < 9 {
		return false, nil
	}

	//log.Printf("%02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3])
	//log.Printf("%02x %02x %02x %02x\n", buf[4], buf[5], buf[6], buf[7])

	if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] >= 0x00 && buf[2] <= 0x03 &&
		buf[5] == 0x01 {
		return true, nil
	}

	return false, nil
}

func StartTls(conn BufferedConn, cert *tls.Certificate) (tlsconn *tls.Conn,
	err error) {
	isTls, err := isHandshake(conn.r)
	if !isTls {
		return nil, err
	}

	config := &tls.Config{
		NextProtos:   []string{"HTTP/1.1"},
		Certificates: []tls.Certificate{*cert},
	}

	tlsconn = tls.Server(conn, config)
	err = tlsconn.Handshake()

	return tlsconn, err
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

	var ipaddrs = []net.IP{}
	ipaddr := net.ParseIP(name)
	if ipaddr != nil {
		ipaddrs = []net.IP{ipaddr}
	}

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
			IPAddresses:  ipaddrs,
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

func isCertificateValid(ca, cert *tls.Certificate, name string) (valid bool) {
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
				if !isCertificateValid(cacert, cert, name) {
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

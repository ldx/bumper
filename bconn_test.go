package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
)

func TestBufferedConn(t *testing.T) {
	log.SetOutput(noLog{})

	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(fmt.Sprintf("Can't start listener: %s\n", err))
		os.Exit(1)
	}
	addr := srv.Addr().String()

	go func() {
		conn, err := srv.Accept()
		if err != nil {
			t.Error(fmt.Sprintf("Accepting client: %s\n", err))
		}
		bconn := newBufferedConn(conn)
		defer bconn.Close()

		pbuf, err := bconn.Peek(64)
		if err != nil {
			t.Error(fmt.Sprintf("Accepting client: %s\n", err))
		}

		rbuf := make([]byte, 64)
		size, err := bconn.Read(rbuf)
		if err != nil {
			t.Error(fmt.Sprintf("Accepting client: %s\n", err))
		} else if size != 64 {
			t.Error(fmt.Sprintf("Got invalid buffer: %s\n", rbuf))
		}

		if bytes.Compare(pbuf, rbuf) != 0 {
			t.Error(fmt.Sprintf("Read() and Peek() differ\n"))
		}

		bconn.Write(rbuf)
	}()

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Error(err)
	}

	buf := make([]byte, 64)
	client.Write(buf)

	reply := make([]byte, 128)
	size, err := client.Read(reply)
	if err != nil {
		t.Error(fmt.Sprintf("Client Read() failed: %s\n", err))
	} else if size != 64 {
		t.Error(fmt.Sprintf("Got invalid reply: %s\n", reply))
	}
}

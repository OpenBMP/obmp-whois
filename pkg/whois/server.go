//  Copyright (c) 2022 Cisco Systems, Inc. and others.  All rights reserved.
package whois

import (
	"bufio"
	"database/sql"
	"github.com/openbmp/obmp-whois/config"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

func Start() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGABRT)

	log.Infof("Starting OpenBMP whois daemon using port %d", config.ListeningPort)
	activeConnections := 0

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: config.ListeningPort})
	if err != nil {
		log.Error(err)
		return
	}
	defer ln.Close()

	db, err := sql.Open("postgres", config.GetPgInfo())
	if err != nil {
		log.Errorf("Error sql.Open(postgres): %s", err)
		return
	}
	defer db.Close()

	db.SetConnMaxLifetime(2 * time.Minute)
	db.SetMaxIdleConns(2)
	db.SetMaxOpenConns(config.MaxThreads)

	threadDoneCh := make(chan bool, config.MaxThreads)
	stopCh := make(chan struct{})

	for {
		acceptedConn := false

		select {
		case sig := <-sigCh:
			log.Infof("Program exiting by signal %s", sig.String())
			close(stopCh)
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)

		default:
			ln.SetDeadline(time.Now().Add(time.Second * 1))
			conn, err := ln.Accept()
			if err != nil {
				switch err := err.(type) {
				case net.Error:
					log.Tracef("timeout waiting for accept, active connections %d", activeConnections)
				default:
					log.Errorf("Error accepting: ", err.Error())
					time.Sleep(200 * time.Millisecond)
				}
			} else {
				acceptedConn = true
			}

			// Check for threads that are done
			for i := 0; i < activeConnections; i++ {
				select {
				case <-threadDoneCh:
					if activeConnections > 0 {
						activeConnections--
					}
				default:
					continue
				}
			}

			if acceptedConn {
				log.Infof("Accepted new connection from %+v", conn.RemoteAddr())

				if activeConnections < config.MaxThreads {
					activeConnections++
				} else {
					log.Warnf("Max threads %d reached. Waiting for a thread to complete", activeConnections)

					// Wait up to 5 seconds before giving up
					acceptedConn = false
					for i := 0; i < 66; i++ {
						select {
						case <-threadDoneCh:
							log.Infof("thread free, continuing to process request")
							acceptedConn = true
							break
						default:
							time.Sleep(30 * time.Millisecond)
						}
					}
				}

				// Accepted conn will be false if an error occurred
				if acceptedConn {
					// Handle connections in a new goroutine.
					go handleRequest(db, conn, stopCh, threadDoneCh)
				} else {
					conn.Write([]byte(config.ErrorOutOfResources))
					conn.Close()
				}
			}
		}
	}
}

func handleRequest(db *sql.DB, conn net.Conn, stopCh <-chan struct{}, threadDoneCh chan<- bool) {
	defer conn.Close()

	var handler Handler
	rd := bufio.NewReader(conn)
	line, isPrefix, err := rd.ReadLine()
	if err != nil {
		log.Warnf("Error reading:", err.Error())
		threadDoneCh <- true
		return
	}

	var cmdRegex strings.Builder

	// Command: Help
	cmdRegex.WriteString("(?i)^help$")
	crxHelp := regexp.MustCompile(cmdRegex.String())
	matched := crxHelp.Match(line)
	if matched {
		log.Debugf("%s: Request help", conn.RemoteAddr())
		conn.Write([]byte(config.HelpUsage))
		threadDoneCh <- true
		return
	}

	// Command: ASN Lookup
	cmdRegex.Reset()
	cmdRegex.WriteString("^(?i)AS[N]*[0-9]+$")
	crxAsn := regexp.MustCompile(cmdRegex.String())
	matched = crxAsn.Match(line)
	if matched {
		log.Debugf("%s: Request ASN lookup", conn.RemoteAddr())
		//handler = AsnHandler{}
		//resp := handler.process(db, conn.RemoteAddr().String(), line, stopCh)
		//conn.Write(resp)
		threadDoneCh <- true
		return
	}

	// Command: IP prefix lookup
	cmdRegex.Reset()
	cmdRegex.WriteString("^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[/][0-9]{1,2}( .+)*$")
	cmdRegex.WriteString("|^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}( .+)*$")

	// Loose IPv6 validation
	cmdRegex.WriteString("|(?i)^(?:[A-F0-9]{1,4}:{1,2})+(?:[A-F0-9]{1,4}){0,1}( .+)*$")
	cmdRegex.WriteString("|(?i)^(?:[A-F0-9]{1,4}:{1,2})+(?:[A-F0-9]{1,4}){0,1}[/][0-9]{1,3}( .+)*$")

	crx_ip := regexp.MustCompile(cmdRegex.String())
	matched = crx_ip.Match(line)
	if matched {
		log.Debugf("%s: Request IP prefix lookup (%s)", conn.RemoteAddr(), line)
		handler = PrefixHandler{}
		resp := handler.process(db, conn.RemoteAddr().String(), line, stopCh)
		conn.Write(resp)
		threadDoneCh <- true
		return
	}

	// Unknown command: If we made it this far, it's an invalid request
	log.Infof("%s: Received %v (%s) is invalid", conn.RemoteAddr(), isPrefix, line)
	conn.Write([]byte(config.ErrorInvalidRequest))
	conn.Write([]byte(config.HelpUsage))

	// Signal that the thread is done and connection is closed
	threadDoneCh <- true
}

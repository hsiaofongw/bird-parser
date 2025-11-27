package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"syscall"
)

func SplitBy(seq []byte) bufio.SplitFunc {
	splitFunc := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, seq); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}
	return splitFunc
}

type Line struct {
	LineIdx      int    `json:"line_idx"`
	LineGroupIdx int    `json:"line_group_idx"`
	Content      string `json:"content"`
	Continuation bool   `json:"continuation"`
	EndOfReply   bool   `json:"end_of_reply"`
}

const maxTokenSize = 1024 * 1024

var socketPath = flag.String("socket", "/var/run/bird/bird.ctl", "path to the socket file")

type RawMessages struct {
	Lines     []Line `json:"lines"`
	NumGroups int    `json:"num_groups"`
}

func testForGroupSep(line string) (hasGroupSeperator bool, continuation bool, endOfReply bool) {
	pattern1 := regexp.MustCompile(`\d{4} `)
	if pattern1.MatchString(line) {
		hasGroupSeperator = true
		endOfReply = true
	}

	pattern2 := regexp.MustCompile(`\d{4}-`)
	if pattern2.MatchString(line) {
		hasGroupSeperator = true
		continuation = true
	}

	return
}

func main() {
	if *socketPath == "" {
		log.Fatalf("socket path is not set")
	}

	conn, err := net.Dial("unix", *socketPath)
	if err != nil {
		log.Fatalf("failed to connect to socket: %v", err)
	}
	defer conn.Close()

	msgs := new(RawMessages)
	msgs.Lines = make([]Line, 0)

	go func() {
		encoder := json.NewEncoder(os.Stdout)
		scanner := bufio.NewScanner(conn)
		scanBuf := make([]byte, maxTokenSize)
		scanner.Buffer(scanBuf, maxTokenSize)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := scanner.Text()
			lineObj := Line{LineIdx: len(msgs.Lines), Content: line, LineGroupIdx: msgs.NumGroups}
			nextGroup, cont, endOfRep := testForGroupSep(line)
			if nextGroup {
				msgs.NumGroups++
				lineObj.Continuation = cont
				lineObj.EndOfReply = endOfRep
			}
			if err := encoder.Encode(lineObj); err != nil {
				log.Fatalf("failed to encode line: %v", err)
			}
			msgs.Lines = append(msgs.Lines, lineObj)
		}
	}()

	go func() {
		io.Copy(os.Stdin, conn)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("received signal %s, shutting down", sig.String())
}

func init() {
	flag.Parse()
}

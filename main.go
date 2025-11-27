package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
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
	LineIdx      int           `json:"line_idx"`
	LineGroupIdx int           `json:"line_group_idx"`
	Raw          string        `json:"raw"`
	Metadata     LineMetadata  `json:"metadata"`
	Meaning      *ReplyMeaning `json:"meaning"`
}

func (l *Line) Content() string {
	return l.Raw[l.Metadata.ContentOffset:]
}

const maxTokenSize = 1024 * 1024

var socketPath = flag.String("socket", "/var/run/bird/bird.ctl", "path to the socket file")

type RawMessages struct {
	Lines  []Line  `json:"lines"`
	Blocks []Block `json:"blocks"`
}

type LineMetadata struct {
	HasGroupSeperator bool   `json:"has_group_seperator"`
	Continuation      bool   `json:"continuation"`
	EndOfReply        bool   `json:"end_of_reply"`
	ContentOffset     int    `json:"content_offset"`
	Code              string `json:"code"`
}

type ReplyMeaning string

const (
	ReplySuccess      ReplyMeaning = "success"
	ReplyTableHeader  ReplyMeaning = "table_header"
	ReplyTableEntries ReplyMeaning = "table_entry"
	ReplyRuntimeError ReplyMeaning = "runtime_error"
	ReplySyntaxError  ReplyMeaning = "syntax_error"
)

func (r *ReplyMeaning) String() string {
	if r == nil {
		return "(unknown)"
	}
	return string(*r)
}

func ReplyMeaningFromCode(code string) (replyMeaning *ReplyMeaning) {
	replyMeaning = new(ReplyMeaning)
	if len(code) > 0 {
		switch code[0:1] {
		case "0":
			*replyMeaning = ReplySuccess
		case "2":
			*replyMeaning = ReplyTableHeader
		case "1":
			*replyMeaning = ReplyTableEntries
		case "8":
			*replyMeaning = ReplyRuntimeError
		case "9":
			*replyMeaning = ReplySyntaxError
		default:
			return nil
		}
		return replyMeaning
	}
	return nil
}

type Block struct {
	BlockIndex int    `json:"block_index"`
	Lines      []Line `json:"lines"`
}

func (b *Block) Content() string {
	lines := make([]string, 0)
	for _, line := range b.Lines {
		lines = append(lines, line.Content())
	}
	return strings.Join(lines, "\n")
}

func testForGroupSep(line string) LineMetadata {
	meta := LineMetadata{}
	meta.ContentOffset = 0

	pattern1 := regexp.MustCompile(`^\d{4} `)
	if pattern1.MatchString(line) {
		meta.HasGroupSeperator = true
		meta.EndOfReply = true
		meta.ContentOffset = 5
		meta.Code = line[:4]
	}

	pattern2 := regexp.MustCompile(`^\d{4}-`)
	if pattern2.MatchString(line) {
		meta.HasGroupSeperator = true
		meta.Continuation = true
		meta.ContentOffset = 5
		meta.Code = line[:4]
	}

	return meta
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

		numLinesRead := 0

		encoder := json.NewEncoder(os.Stdout)
		scanner := bufio.NewScanner(conn)
		scanBuf := make([]byte, maxTokenSize)
		scanner.Buffer(scanBuf, maxTokenSize)
		scanner.Split(SplitBy([]byte{'\n'}))
		for scanner.Scan() {
			line := scanner.Text()
			lineObj := Line{LineIdx: len(msgs.Lines), Raw: line, LineGroupIdx: len(msgs.Blocks)}
			lineObj.Metadata = testForGroupSep(line)
			lineObj.Meaning = ReplyMeaningFromCode(lineObj.Metadata.Code)
			msgs.Lines = append(msgs.Lines, lineObj)
			if lineObj.Metadata.HasGroupSeperator && lineObj.Metadata.EndOfReply {
				blockObj := Block{
					BlockIndex: len(msgs.Blocks),
					Lines:      msgs.Lines[numLinesRead:],
				}
				msgs.Blocks = append(msgs.Blocks, blockObj)
				if err := encoder.Encode(blockObj); err != nil {
					log.Fatalf("failed to encode line: %v", err)
				}
				numLinesRead = len(msgs.Lines)
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := scanner.Text()
			conn.Write([]byte(line + "\n"))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("received signal %s, shutting down", sig.String())
}

func init() {
	flag.Parse()
}

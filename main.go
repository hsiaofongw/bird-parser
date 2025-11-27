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
	"strconv"
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
	Indent       int           `json:"indent"`
	Content      string        `json:"content"`
	TrimmedLine  string        `json:"trimmed_line"`
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

type ChannelRoutesStat struct {
	Imported  int `json:"imported"`
	Filtered  int `json:"filtered"`
	Exported  int `json:"exported"`
	Preferred int `json:"preferred"`
}

type ChannelRouteChangesStatEntry struct {
	Received *int `json:"received,omitempty"`
	Rejected *int `json:"rejected,omitempty"`
	Filtered *int `json:"filtered,omitempty"`
	Ignored  *int `json:"ignored,omitempty"`
	Accepted *int `json:"accepted,omitempty"`
}

type ChannelRouteChangesStat struct {
	ImportUpdates   *ChannelRouteChangesStatEntry `json:"import_updates,omitempty"`
	ImportWithdraws *ChannelRouteChangesStatEntry `json:"import_withdraws,omitempty"`
	ExportUpdates   *ChannelRouteChangesStatEntry `json:"export_updates,omitempty"`
	ExportWithdraws *ChannelRouteChangesStatEntry `json:"export_withdraws,omitempty"`
}

type BGPProtoInfo struct {
	Channels map[string]ChannelInfo `json:"channels"`
}

func parseBGPProtoInfo(lines []Line) *BGPProtoInfo {
	result := new(BGPProtoInfo)
	result.Channels = make(map[string]ChannelInfo)
	if lineIdx := findLineIdx(lines, `^Channel ipv6`); lineIdx >= 0 {
		channelInfo := parseChannel(lines[lineIdx : lineIdx+13])
		if channelInfo != nil {
			result.Channels[channelInfo.Name] = *channelInfo
		}
	}
	if lineIdx := findLineIdx(lines, `^Channel ipv4`); lineIdx >= 0 {
		channelInfo := parseChannel(lines[lineIdx : lineIdx+13])
		if channelInfo != nil {
			result.Channels[channelInfo.Name] = *channelInfo
		}
	}
	return result
}

type ChannelInfo struct {
	Name             string                   `json:"name"`
	State            string                   `json:"state"`
	Preference       *int                     `json:"preference,omitempty"`
	InputFilter      string                   `json:"input_filter"`
	OutputFilter     string                   `json:"output_filter"`
	RoutesStat       *ChannelRoutesStat       `json:"routes_stat,omitempty"`
	RouteChangesStat *ChannelRouteChangesStat `json:"route_changes_stat,omitempty"`
	BGPNextHop       *string                  `json:"bgp_next_hop,omitempty"`
}

func parseRouteStats(line string) *ChannelRoutesStat {
	result := new(ChannelRoutesStat)
	numMatches := 0

	importedPattern := regexp.MustCompile(`(\d+)\s+imported`)
	if matches := importedPattern.FindStringSubmatch(line); matches != nil {
		imported, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Imported = imported
			numMatches++
		}
	}

	filteredPattern := regexp.MustCompile(`(\d+)\s+filtered`)
	if matches := filteredPattern.FindStringSubmatch(line); matches != nil {
		filtered, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Filtered = filtered
			numMatches++
		}
	}

	exportedPattern := regexp.MustCompile(`(\d+)\s+exported`)
	if matches := exportedPattern.FindStringSubmatch(line); matches != nil {
		exported, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Exported = exported
			numMatches++
		}
	}

	preferredPattern := regexp.MustCompile(`(\d+)\s+preferred`)
	if matches := preferredPattern.FindStringSubmatch(line); matches != nil {
		preferred, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Preferred = preferred
			numMatches++
		}
	}

	if numMatches == 0 {
		return nil
	}

	return result
}

func parseNums(line string) []*int {
	segs := strings.Split(line, " ")
	result := make([]*int, 0)
	for _, seg := range segs {
		word := strings.TrimSpace(seg)
		if word == "" {
			continue
		}
		if x, err := strconv.Atoi(word); err == nil {
			result = append(result, &x)
		} else {
			result = append(result, nil)
		}
	}
	return result
}

func parseRouteChangesStatEntry(importUpdatesLine string) *ChannelRouteChangesStatEntry {
	nums := parseNums(importUpdatesLine)
	if len(nums) == 0 {
		return nil
	}
	updateStats := new(ChannelRouteChangesStatEntry)
	if len(nums) > 0 {
		updateStats.Received = nums[0]
	}
	if len(nums) > 1 {
		updateStats.Rejected = nums[1]
	}
	if len(nums) > 2 {
		updateStats.Filtered = nums[2]
	}
	if len(nums) > 3 {
		updateStats.Ignored = nums[3]
	}
	if len(nums) > 4 {
		updateStats.Accepted = nums[4]
	}
	return updateStats
}

func findLineIdx(lines []Line, pattern string) int {
	patternObj := regexp.MustCompile(pattern)
	for i, line := range lines {
		if patternObj.MatchString(line.TrimmedLine) {
			return i
		}
	}
	return -1
}

func matchPrefix(prefixPattern string, line string) string {
	pattern := regexp.MustCompile(prefixPattern)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 0 {
		match0 := matches[0]
		return strings.TrimSpace(line[len(match0):])
	}
	return ""
}

func parseChannel(lines []Line) *ChannelInfo {
	channelInfo := new(ChannelInfo)

	for _, lineObj := range lines {
		line := lineObj.TrimmedLine
		if channelName := matchPrefix(`^Channel\s+`, line); channelName != "" {
			channelInfo.Name = channelName
		} else if state := matchPrefix(`^State:\s+`, line); state != "" {
			channelInfo.State = state
		} else if pref := matchPrefix(`^Preference:\s+`, line); pref != "" {
			prefInt, err := strconv.Atoi(pref)
			if err == nil {
				channelInfo.Preference = &prefInt
			}
		} else if inputFilter := matchPrefix(`^Input filter:\s+`, line); inputFilter != "" {
			channelInfo.InputFilter = inputFilter
		} else if outputFilter := matchPrefix(`^Output filter:\s+`, line); outputFilter != "" {
			channelInfo.OutputFilter = outputFilter
		} else if routeStatLine := matchPrefix(`^Routes:\s+`, line); routeStatLine != "" {
			channelInfo.RoutesStat = parseRouteStats(routeStatLine)
		} else if routeChangesStatLine := matchPrefix(`^Route changes:\s+`, line); routeChangesStatLine != "" {
			continue
		} else if importUpdates := matchPrefix(`^Import updates:\s+`, line); importUpdates != "" {
			if entry := parseRouteChangesStatEntry(importUpdates); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ImportUpdates = entry
			}
		} else if importWithdraws := matchPrefix(`^Import withdraws:\s+`, line); importWithdraws != "" {
			if entry := parseRouteChangesStatEntry(importWithdraws); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ImportWithdraws = entry
			}
		} else if exportUpdates := matchPrefix(`^Export updates:\s+`, line); exportUpdates != "" {
			if entry := parseRouteChangesStatEntry(exportUpdates); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ExportUpdates = entry
			}
		} else if exportWithdraws := matchPrefix(`^Export withdraws:\s+`, line); exportWithdraws != "" {
			if entry := parseRouteChangesStatEntry(exportWithdraws); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ExportWithdraws = entry
			}
		} else if bgpNextHop := matchPrefix(`^BGP Next hop:\s+`, line); bgpNextHop != "" {
			channelInfo.BGPNextHop = &bgpNextHop
		}
	}

	return channelInfo
}

func (b *Block) Content() string {
	lines := make([]string, 0)
	for _, line := range b.Lines {
		lines = append(lines, line.Content)
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

func countIndent(line string) int {
	pattern := regexp.MustCompile(`^\s*`)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 0 {
		return len(matches[0])
	}
	return 0
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
			lineObj.Content = lineObj.Raw[lineObj.Metadata.ContentOffset:]
			lineObj.Indent = countIndent(lineObj.Content)
			lineObj.TrimmedLine = strings.TrimSpace(lineObj.Content)
			msgs.Lines = append(msgs.Lines, lineObj)
			if lineObj.Metadata.HasGroupSeperator && lineObj.Metadata.EndOfReply {
				blockObj := Block{
					BlockIndex: len(msgs.Blocks),
					Lines:      msgs.Lines[numLinesRead:],
				}
				msgs.Blocks = append(msgs.Blocks, blockObj)
				numLinesRead = len(msgs.Lines)

				protoInfo := parseBGPProtoInfo(blockObj.Lines)
				if protoInfo != nil {
					if err := encoder.Encode(protoInfo); err != nil {
						log.Fatalf("failed to encode proto info: %v", err)
					}
				}
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

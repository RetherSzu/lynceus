package parser

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"DFIRFlow/internal/normalizer"
)

// fakeParser exerce tout le contrat sans artefact réel (research.md R7).
// Format : "FAKE1\n" puis une ligne par enregistrement
// "numéro|horodatage RFC 3339|event_type|commande" ; "!" = illisible.
type fakeParser struct{}

const fakeMagic = "FAKE1\n"

func (fakeParser) Name() string { return "fake" }

func (fakeParser) Match(head []byte) bool { return bytes.HasPrefix(head, []byte(fakeMagic)) }

func (fakeParser) Parse(ctx context.Context, r io.ReaderAt, size int64, src Source, out Sink) error {
	br := bufio.NewReader(io.NewSectionReader(r, 0, size))
	if head, err := br.ReadString('\n'); head != fakeMagic {
		if err != nil && err != io.EOF {
			return err
		}
		return errors.New("fake: unrecognized format")
	}
	host, fqdn := normalizer.NormalizeHost(src.Host)
	next := uint64(1)
	for n := 2; ; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := br.ReadString('\n')
		if line == "" && err == io.EOF {
			return nil
		}
		if err != nil && err != io.EOF {
			return err
		}
		loc := "line=" + strconv.Itoa(n)
		if err == io.EOF {
			return out.Anomaly(Anomaly{Locator: loc, Kind: KindTruncated, Message: "record not terminated"})
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "!" {
			next++
			if err := out.Anomaly(Anomaly{Locator: loc, Kind: KindUnreadable, Message: "unreadable record"}); err != nil {
				return err
			}
			continue
		}
		f := strings.SplitN(line, "|", 4)
		var num uint64
		var ts time.Time
		if len(f) == 4 {
			num, err = strconv.ParseUint(f[0], 10, 64)
			if err == nil && f[1] != "" {
				ts, err = time.Parse(time.RFC3339Nano, f[1])
			}
		}
		if len(f) != 4 || err != nil || num < next {
			if err := out.Anomaly(Anomaly{Locator: loc, Kind: KindUnreadable, Message: "malformed record"}); err != nil {
				return err
			}
			next++
			continue
		}
		for ; next < num; next++ {
			if err := out.Anomaly(Anomaly{Locator: "record=" + strconv.FormatUint(next, 10), Kind: KindMissing, Message: "record absent from input"}); err != nil {
				return err
			}
		}
		next = num + 1
		// Un horodatage vide donne un événement invalide, émis tel quel : c'est
		// au Sink de validation de le convertir en anomalie.
		e := normalizer.Event{
			UID:           normalizer.UID(src.SHA256, src.File, loc),
			Timestamp:     normalizer.Time{Time: ts},
			TimestampType: normalizer.TSCreated,
			Source:        normalizer.SourceMFT,
			EventType:     f[2],
			Host:          host,
			HostFQDN:      fqdn,
			CommandLine:   f[3],
			SourceFile:    src.File,
			SourceHash:    src.SHA256,
			RecordID:      num,
			RecordLocator: loc,
			Ingest:        normalizer.IngestNative,
		}
		if err := out.Event(e); err != nil {
			return err
		}
	}
}

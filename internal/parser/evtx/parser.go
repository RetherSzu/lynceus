// Package evtx est le parser natif des journaux d'événements Windows (spec
// 005). Le décodage bas niveau est dans binxml (fork de Velocidex/evtx).
package evtx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"DFIRFlow/internal/normalizer"
	"DFIRFlow/internal/parser"
	"DFIRFlow/internal/parser/evtx/binxml"
)

// Parser implémente parser.Parser pour le format EVTX.
type Parser struct{}

func (Parser) Name() string { return normalizer.SourceEVTX }

func (Parser) Match(head []byte) bool {
	return bytes.HasPrefix(head, []byte(binxml.EVTX_HEADER_MAGIC))
}

// Parse décode le journal chunk par chunk, dans l'ordre (FR-007), et émet un
// événement ou une anomalie par enregistrement annoncé (FR-008).
func (Parser) Parse(ctx context.Context, r io.ReaderAt, size int64, src parser.Source, out parser.Sink) error {
	tbl, err := defaultTable()
	if err != nil {
		return err
	}
	f, err := binxml.OpenFile(r, size)
	if err != nil {
		return err
	}
	for i := 0; i < f.NumChunks; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := f.ReadChunk(i)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if e.Lost != nil {
				loc := fmt.Sprintf("chunk:%d", i)
				if e.Lost.Number != 0 {
					loc += fmt.Sprintf("/record:%d", e.Lost.Number)
				}
				err = out.Anomaly(parser.Anomaly{Locator: loc, Kind: e.Lost.Kind, Message: e.Lost.Message})
			} else {
				ev, cerr := toEvent(e.Record, i, src, tbl)
				if cerr != nil {
					err = out.Anomaly(parser.Anomaly{Locator: locator(i, e.Record), Kind: parser.KindUnreadable, Message: cerr.Error()})
				} else {
					err = out.Event(ev)
				}
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func locator(chunk int, rec *binxml.EventRecord) string {
	return fmt.Sprintf("chunk:%d/record:%d", chunk, rec.Header.RecordID)
}

// toEvent convertit un enregistrement décodé en événement normalisé
// (data-model.md). La validation est faite par parser.Validating.
func toEvent(rec *binxml.EventRecord, chunk int, src parser.Source, tbl Table) (normalizer.Event, error) {
	root, _ := rec.Event.(*binxml.Dict)
	if root == nil {
		return normalizer.Event{}, errors.New("record without Event element")
	}
	evAny, _ := root.Get("Event")
	evDict, _ := evAny.(*binxml.Dict)
	if evDict == nil {
		return normalizer.Event{}, errors.New("record without Event element")
	}
	sysAny, _ := evDict.Get("System")
	sys, _ := sysAny.(*binxml.Dict)
	if sys == nil {
		return normalizer.Event{}, errors.New("record without System element")
	}

	metadata := map[string]string{}
	data := map[string]interface{}{} // valeurs typées de EventData / UserData
	flatten("System", sys, metadata, nil)
	if v, ok := evDict.Get("EventData"); ok {
		eventData(v, metadata, data)
	}
	if v, ok := evDict.Get("UserData"); ok {
		if d, ok := v.(*binxml.Dict); ok {
			for _, k := range d.Keys() { // élément racine de UserData omis
				child, _ := d.Get(k)
				flatten("", child, metadata, data)
			}
		}
	}

	ev := normalizer.Event{
		Source:        normalizer.SourceEVTX,
		EventType:     normalizer.TypeOther,
		Channel:       metadata["System.Channel"],
		Provider:      metadata["System.Provider.Name"],
		SourceFile:    src.File,
		SourceHash:    src.SHA256,
		RecordID:      rec.Header.RecordID,
		RecordLocator: locator(chunk, rec),
		Ingest:        normalizer.IngestNative,
		Metadata:      metadata,
	}
	ev.UID = normalizer.UID(src.SHA256, src.File, ev.RecordLocator)
	if id, ok := parseEventID(metadata["System.EventID"]); ok {
		ev.EventID = &id
	}
	computer := metadata["System.Computer"]
	if computer == "" {
		computer = src.Host
	}
	ev.Host, ev.HostFQDN = normalizer.NormalizeHost(computer)

	logged, _ := timeOf(value(sys, "TimeCreated", "SystemTime"))
	ev.Timestamp, ev.TimestampType = normalizer.Time{Time: logged}, normalizer.TSLogged
	if ev.EventID != nil {
		if entry, ok := tbl.lookup(ev.Channel, ev.Provider, *ev.EventID); ok {
			if action, ok := entry.apply(&ev, data); ok {
				ev.Timestamp, ev.TimestampType = normalizer.Time{Time: action}, entry.ActionTimeType
			}
		}
	}

	// Horodatages secondaires distincts du principal (FR-010) ; un en-tête nul est omis (C1).
	secondary := func(t time.Time, typ, origin string) {
		if t.IsZero() || t.Truncate(time.Microsecond).Equal(ev.Timestamp.Truncate(time.Microsecond)) {
			return
		}
		ev.Timestamps = append(ev.Timestamps, normalizer.TimestampEntry{Type: typ, Time: normalizer.Time{Time: t}, Origin: origin})
	}
	if ev.TimestampType != normalizer.TSLogged {
		secondary(logged, normalizer.TSLogged, "TimeCreated")
	}
	secondary(binxml.FileTime(rec.Header.FileTime).Time(), normalizer.TSWritten, "RecordHeader")
	return ev, nil
}

// value suit un chemin d'éléments dans l'arbre décodé.
func value(d *binxml.Dict, path ...string) interface{} {
	var v interface{} = d
	for _, k := range path {
		cur, ok := v.(*binxml.Dict)
		if !ok {
			return nil
		}
		v, _ = cur.Get(k)
	}
	return v
}

func parseEventID(s string) (uint32, bool) {
	var id uint32
	if _, err := fmt.Sscan(s, &id); err != nil || fmt.Sprint(id) != s {
		return 0, false
	}
	return id, true
}

// flatten aplatit un sous-arbre dans metadata (clés jointes par ".", texte
// d'un élément sous le nom de l'élément) et, si data n'est pas nil, garde les
// valeurs typées pour la table de correspondance.
func flatten(prefix string, v interface{}, metadata map[string]string, data map[string]interface{}) {
	join := func(k string) string {
		if prefix == "" {
			return k
		}
		if k == "Value" {
			return prefix
		}
		return prefix + "." + k
	}
	switch x := v.(type) {
	case *binxml.Dict:
		for _, k := range x.Keys() {
			child, _ := x.Get(k)
			flatten(join(k), child, metadata, data)
		}
	case []interface{}:
		for i, child := range x {
			flatten(fmt.Sprintf("%s[%d]", prefix, i+1), child, metadata, data)
		}
	default:
		if prefix == "" {
			return
		}
		metadata[prefix] = render(x)
		if data != nil {
			data[prefix] = x
		}
	}
}

// eventData aplatit EventData : <Data Name="X"> sous X, données sans nom
// sous Data[1], Data[2]… (spec 003, FR-013).
func eventData(v interface{}, metadata map[string]string, data map[string]interface{}) {
	d, ok := v.(*binxml.Dict)
	if !ok {
		flatten("Data[1]", v, metadata, data)
		return
	}
	for _, k := range d.Keys() {
		child, _ := d.Get(k)
		if k != "Data" {
			flatten(k, child, metadata, data)
			continue
		}
		items, ok := child.([]interface{})
		if !ok {
			items = []interface{}{child}
		}
		for i, item := range items {
			name := fmt.Sprintf("Data[%d]", i+1)
			var val interface{} = item
			if it, ok := item.(*binxml.Dict); ok {
				if n, ok := it.Get("Name"); ok {
					name = render(n)
					val, _ = it.Get("Value")
					if val == nil {
						val = ""
					}
				}
			}
			flatten(name, val, metadata, data)
		}
	}
}

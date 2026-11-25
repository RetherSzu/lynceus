/*
Copyright 2018 Velocidex Innovations

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Modifié pour DFIRFlow (voir NOTICE) : lecture par io.ReaderAt, comptage
des enregistrements par chunk, bornes, absence de panique, valeurs typées.
*/
package binxml

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	EVTX_HEADER_MAGIC       = "ElfFile\x00"
	EVTX_CHUNK_HEADER_MAGIC = "ElfChnk\x00"
	EVTX_CHUNK_HEADER_SIZE  = 0x200

	EVTX_CHUNK_SIZE = 0x10000

	EVTX_EVENT_RECORD_MAGIC = "\x2a\x2a\x00\x00"
	EVTX_EVENT_RECORD_SIZE  = 24

	evtxFileHeaderSize = 128
	// Un enregistrement tient dans un chunk, après son en-tête.
	maxRecordSize = EVTX_CHUNK_SIZE - EVTX_CHUNK_HEADER_SIZE
	maxRecords    = maxRecordSize / EVTX_EVENT_RECORD_SIZE
	maxDepth      = 64
)

// Types des valeurs décodées, pour un rendu fidèle à la vue XML Windows.
type (
	HexInt32   uint32
	HexInt64   uint64
	FileTime   uint64 // Intervalles de 100 ns depuis 1601-01-01 UTC
	SystemTime time.Time
	GUID       EvtxGUID
	SID        string
	Binary     []byte
)

// Time convertit un FILETIME en instant UTC ; zéro reste l'instant nul.
func (ft FileTime) Time() time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDelta = 116444736000000000 // 1601 → 1970 en 100 ns
	v := int64(ft) - epochDelta
	return time.Unix(v/1e7, (v%1e7)*100).UTC()
}

type EvtxGUID struct {
	D  uint32
	W1 uint16
	W2 uint16
	B  [8]uint8
}

func (self *EvtxGUID) ToString() string {
	return fmt.Sprintf(
		"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		self.D, self.W1, self.W2,
		self.B[0], self.B[1], self.B[2], self.B[3],
		self.B[4], self.B[5], self.B[6], self.B[7])
}

// EVTXHeader : ChunkCount ajouté à sa place réelle (décalage 42).
type EVTXHeader struct {
	Magic           [8]byte
	Firstchunk      uint64
	LastChunk       uint64
	NextRecordID    uint64
	HeaderSize      uint32
	MinorVersion    uint16
	MajorVersion    uint16
	HeaderBlockSize uint16
	ChunkCount      uint16
	_               [76]byte
	FileFlags       uint32
	CheckSum        uint32
}

type EventRecordHeader struct {
	Magic    [4]byte
	Size     uint32
	RecordID uint64
	FileTime uint64
}

type EventRecord struct {
	Header EventRecordHeader
	Event  interface{}
}

func (self *EventRecord) Parse(ctx *ParseContext) {
	template := ctx.NewTemplate(0)
	ParseBinXML(ctx)

	self.Event = template.Expand(nil)
}

type ChunkHeader struct {
	Magic               [8]byte
	FirstEventRecNumber uint64
	LastEventRecNumber  uint64
	FirstEventRecID     uint64
	LastEventRecID      uint64
	HeaderSize          uint32
}

// Causes d'une perte d'enregistrement (spec 003, FR-016).
const (
	LostUnreadable = "unreadable"
	LostMissing    = "missing"
	LostTruncated  = "truncated"
)

// Lost décrit un enregistrement annoncé par l'en-tête du chunk mais non
// décodé. Number vaut 0 pour une perte qui concerne le chunk entier.
type Lost struct {
	Number  uint64
	Kind    string
	Message string
}

// File est un journal EVTX ouvert en lecture par position.
type File struct {
	r         io.ReaderAt
	size      int64
	Header    EVTXHeader
	NumChunks int
}

// OpenFile vérifie l'en-tête de fichier. Le nombre de chunks est déduit de la
// taille du fichier, jamais de l'en-tête (borne contre un en-tête falsifié).
func OpenFile(r io.ReaderAt, size int64) (*File, error) {
	f := &File{r: r, size: size}
	if size < evtxFileHeaderSize {
		return nil, errors.New("truncated file header")
	}
	buf := make([]byte, evtxFileHeaderSize)
	if _, err := r.ReadAt(buf, 0); err != nil {
		return nil, fmt.Errorf("read file header: %w", err)
	}
	_ = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &f.Header)
	if string(f.Header.Magic[:]) != EVTX_HEADER_MAGIC {
		return nil, errors.New("not an EVTX file (wrong magic)")
	}
	if !is_supported(f.Header.MinorVersion, f.Header.MajorVersion) {
		return nil, fmt.Errorf("unsupported EVTX version %d.%d", f.Header.MajorVersion, f.Header.MinorVersion)
	}
	block := int64(f.Header.HeaderBlockSize)
	if block < evtxFileHeaderSize {
		return nil, fmt.Errorf("invalid header block size %d", block)
	}
	if size < block {
		return nil, errors.New("truncated file header")
	}
	f.NumChunks = int((size - block + EVTX_CHUNK_SIZE - 1) / EVTX_CHUNK_SIZE)
	return f, nil
}

// Entry est un enregistrement lu (Record) ou annoncé et non lu (Lost).
type Entry struct {
	Record *EventRecord
	Lost   *Lost
}

// ReadChunk décode le chunk i et renvoie, dans l'ordre du journal, chaque
// enregistrement annoncé par l'en-tête du chunk : lu, ou perdu avec sa cause.
// Un chunk inutilisé (rempli de zéros ou marqué vide) ne renvoie rien. err ne
// signale qu'une erreur d'entrée/sortie.
func (f *File) ReadChunk(i int) (entries []Entry, err error) {
	offset := int64(f.Header.HeaderBlockSize) + int64(i)*EVTX_CHUNK_SIZE
	buf := make([]byte, EVTX_CHUNK_SIZE)
	n, err := f.r.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read chunk %d: %w", i, err)
	}
	buf = buf[:n]
	if n < EVTX_CHUNK_HEADER_SIZE {
		if allZero(buf) {
			return nil, nil
		}
		return []Entry{{Lost: &Lost{Kind: LostTruncated, Message: fmt.Sprintf("chunk header truncated (%d bytes)", n)}}}, nil
	}

	header := ChunkHeader{}
	_ = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &header)
	if string(header.Magic[:]) != EVTX_CHUNK_HEADER_MAGIC {
		if allZero(buf) {
			return nil, nil
		}
		return []Entry{{Lost: &Lost{Kind: LostUnreadable, Message: "invalid chunk signature"}}}, nil
	}
	if header.LastEventRecID == 0xffffffffffffffff {
		return nil, nil
	}
	// Les pertes sont numérotées comme les enregistrements : par identifiant.
	first, last := header.FirstEventRecID, header.LastEventRecID
	if last < first || last-first >= maxRecords {
		return []Entry{{Lost: &Lost{Kind: LostUnreadable, Message: fmt.Sprintf("invalid record range %d-%d", first, last)}}}, nil
	}

	chunk := &Chunk{Header: header, Offset: offset}
	ctx := NewParseContext(chunk)
	ctx.buff = buf
	ctx.offset = EVTX_CHUNK_HEADER_SIZE

	lose := func(from uint64, kind, msg string) {
		for k := from; k <= last; k++ {
			entries = append(entries, Entry{Lost: &Lost{Number: k, Kind: kind, Message: msg}})
			if k == math.MaxUint64 {
				break
			}
		}
	}
	for num := first; num <= last; num++ {
		start := ctx.Offset()
		if start+EVTX_EVENT_RECORD_SIZE > len(buf) {
			lose(num, LostTruncated, "record beyond end of file")
			break
		}
		rec := &EventRecord{}
		_ = binary.Read(bytes.NewReader(buf[start:start+EVTX_EVENT_RECORD_SIZE]), binary.LittleEndian, &rec.Header)
		size := int(rec.Header.Size)
		if string(rec.Header.Magic[:]) != EVTX_EVENT_RECORD_MAGIC || size < EVTX_EVENT_RECORD_SIZE || size > maxRecordSize || start+size > EVTX_CHUNK_SIZE {
			entries = append(entries, Entry{Lost: &Lost{Number: num, Kind: LostUnreadable, Message: "invalid record header"}})
			lose(num+1, LostMissing, "not reached after an unreadable record")
			break
		}
		if start+size > len(buf) {
			lose(num, LostTruncated, "record beyond end of file")
			break
		}
		ctx.SetOffset(start + EVTX_EVENT_RECORD_SIZE)
		if msg := parseRecord(ctx, rec); msg != "" {
			entries = append(entries, Entry{Lost: &Lost{Number: num, Kind: LostUnreadable, Message: msg}})
		} else {
			entries = append(entries, Entry{Record: rec})
		}
		ctx.SetOffset(start + size)
		if num == math.MaxUint64 {
			break
		}
	}
	return entries, nil
}

// parseRecord décode le BinXML d'un enregistrement ; toute panique résiduelle
// ou lecture hors limites devient un message d'erreur.
func parseRecord(ctx *ParseContext, rec *EventRecord) (msg string) {
	*ctx.bad = false
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprintf("decoding error: %v", r)
		}
	}()
	rec.Parse(ctx)
	if *ctx.bad {
		return "malformed BinXML (out of bounds)"
	}
	return ""
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

type Chunk struct {
	Header ChunkHeader
	Offset int64
}

type TemplateNode struct {
	Id          uint32
	Type        uint32
	Literal     interface{}
	NestedArray []*TemplateNode
	NestedDict  *Dict //map[string]*TemplateNode

	CurrentKey string
}

func (self *TemplateNode) Expand(args map[int]interface{}) interface{} {
	if self.NestedDict != nil {
		result := NewDict()
		for _, k := range self.NestedDict.Keys() {
			v, _ := self.NestedDict.Get(k)
			expanded := v.(*TemplateNode).Expand(args)
			if k == "" {
				k = "Value"
				if self.NestedDict.Len() == 1 {
					return expanded
				}

				expanded_dict, ok := expanded.(*Dict)
				if ok {
					for _, k := range expanded_dict.Keys() {
						v, _ := expanded_dict.Get(k)
						if v != nil {
							result.Set(k, v)
						}
					}
					continue
				}
			}
			if expanded != nil {
				result.Set(k, expanded)
			}
		}
		return result

	} else if self.Literal != nil {
		return self.Literal

	} else if self.NestedArray != nil {
		result := []interface{}{}
		for _, i := range self.NestedArray {
			result = append(result, i.Expand(args))
		}
		return result

	} else if args != nil {
		value, pres := args[int(self.Id)]
		if !pres {
			return nil
		}

		return value
	}

	return nil
}

func (self *TemplateNode) SetLiteral(key string, literal interface{}) {
	if self.NestedDict == nil {
		self.NestedDict = NewDict() //make(map[string]*TemplateNode)
	}

	// Ignore useless xmlsn attributes.
	if key != "xmlns" {
		self.NestedDict.Set(key, &TemplateNode{Literal: literal})
	}
}

func (self *TemplateNode) SetExpansion(key string, id, type_id uint32) {
	if self.NestedDict == nil {
		self.NestedDict = NewDict() //make(map[string]*TemplateNode)
	}

	self.NestedDict.Set(key, &TemplateNode{Id: id, Type: type_id})
}

func (self *TemplateNode) SetNested(key string, nested *TemplateNode) {
	if self.NestedDict == nil {
		self.NestedDict = NewDict() //make(map[string]*TemplateNode)
	}

	existing_any, pres := self.NestedDict.Get(key)
	if pres {
		existing := existing_any.(*TemplateNode)

		// If there is already a nested value we append it.
		if existing.NestedArray != nil {
			existing.NestedArray = append(existing.NestedArray, nested)
			return
		}

		// Otherwise we convert the existing value to an array
		// and append the new value on it.
		nested = &TemplateNode{
			NestedArray: []*TemplateNode{existing, nested},
		}
	}
	self.NestedDict.Set(key, nested)
}

func NewTemplate(id int) *TemplateNode {
	result := TemplateNode{}
	return &result
}

type ParseContext struct {
	buff   []byte
	offset int

	root *TemplateNode

	// XML Attributes are written to this template.
	stack []*TemplateNode

	attribute_mode bool

	chunk *Chunk

	// Modèles déjà vus dans ce chunk, indexés par leur position de définition.
	knownIDs map[int]*TemplateNode

	// bad est partagé par les copies : une lecture hors limites invalide
	// l'enregistrement en cours. depth borne l'imbrication.
	bad   *bool
	depth int
}

func (self *ParseContext) CurrentKey() string {
	if !self.attribute_mode {
		return ""
	}
	return self.CurrentTemplate().CurrentKey
}

func (self *ParseContext) Offset() int {
	return self.offset
}

func (self *ParseContext) SetOffset(offset int) {
	self.offset = offset
}

func (self *ParseContext) PushTemplate(key string, template *TemplateNode) {
	debug("PushTemplate: %x -> %x\n", len(self.stack), len(self.stack)+1)
	current := self.CurrentTemplate()
	current.SetNested(key, template)
	self.stack = append(self.stack, template)
}

func (self *ParseContext) CurrentTemplate() *TemplateNode {
	if len(self.stack) > 0 {
		return self.stack[len(self.stack)-1]
	}
	return NewTemplate(0)
}

func (self *ParseContext) PopTemplate() {
	if len(self.stack) > 0 {
		debug("PopTemplate: %x -> %x\n", len(self.stack), len(self.stack)-1)
		self.stack = self.stack[:len(self.stack)-1]
	}
}

func NewParseContext(chunk *Chunk) *ParseContext {
	template := NewTemplate(0)
	bad := false
	result := ParseContext{
		root:     template,
		stack:    []*TemplateNode{template},
		chunk:    chunk,
		knownIDs: make(map[int]*TemplateNode),
		bad:      &bad,
	}

	return &result
}

// available indique si size octets peuvent être lus ; sinon l'enregistrement
// est marqué invalide.
func (self *ParseContext) available(size int) bool {
	if size < 0 || self.offset < 0 || self.offset+size > len(self.buff) {
		*self.bad = true
		return false
	}
	return true
}

func (self *ParseContext) ConsumeUint8() uint8 {
	if !self.available(1) {
		return 0
	}
	result := self.buff[self.offset]
	self.offset++
	return result
}

func (self *ParseContext) ConsumeUint16() uint16 {
	if !self.available(2) {
		return 0
	}

	result := binary.LittleEndian.Uint16(self.buff[self.offset:])
	self.offset += 2
	return result
}

func (self *ParseContext) ConsumeUint32() uint32 {
	if !self.available(4) {
		return 0
	}

	result := binary.LittleEndian.Uint32(self.buff[self.offset:])
	self.offset += 4
	return result
}

func (self *ParseContext) ConsumeUint64() uint64 {
	if !self.available(8) {
		return 0
	}

	result := binary.LittleEndian.Uint64(self.buff[self.offset:])
	self.offset += 8
	return result
}

// ConsumeBytes ne fait jamais d'allocation de la taille lue dans le fichier :
// hors limites, elle renvoie nil et marque l'enregistrement invalide.
func (self *ParseContext) ConsumeBytes(size int) []byte {
	if !self.available(size) {
		return nil
	}

	result := self.buff[self.offset : self.offset+size]
	self.offset += size
	return result
}

func (self *ParseContext) SkipBytes(count int) {
	if self.available(count) {
		self.offset += count
	}
}

// Make a copy of the context. This new copy can be used to continue
// parsing without disturbing the state of this parser context.
func (self ParseContext) Copy() *ParseContext {
	result := NewParseContext(self.chunk)
	result.buff = self.buff
	result.offset = self.offset
	result.knownIDs = self.knownIDs
	result.bad = self.bad
	result.depth = self.depth + 1
	return result
}

func (self *ParseContext) NewTemplate(id int) *TemplateNode {
	self.root = NewTemplate(id)
	self.stack = []*TemplateNode{self.root}

	if id != 0 {
		self.knownIDs[id] = self.root
	}

	return self.root
}

func (self *ParseContext) GetTemplateByID(id int) (*TemplateNode, bool) {
	template, pres := self.knownIDs[id]
	return template, pres
}

func UTF16LEToUTF8(data []byte) []byte {
	if len(data) == 0 || len(data)%2 == 1 {
		return data
	}

	buff := make([]uint16, len(data)/2)
	for i := range buff {
		buff[i] = uint16(data[i*2]) + (uint16(data[i*2+1]) << 8)
	}
	for len(buff) > 0 && buff[len(buff)-1] == 0 {
		buff = buff[:len(buff)-1]
	}

	return []byte(string(utf16.Decode(buff)))
}

func ReadPrefixedUnicodeString(ctx *ParseContext, is_null_terminated bool) string {
	debug("ReadPrefixedUnicodeString Enter: %x\n", ctx.Offset())
	count := int(ctx.ConsumeUint16())
	if is_null_terminated {
		count += 1
	}
	debug("ReadPrefixedUnicodeString count: %d\n", count)
	buffer := ctx.ConsumeBytes(count * 2)
	result := UTF16LEToUTF8(buffer)
	debug("ReadPrefixedUnicodeString exit: %x %s\n", ctx.Offset(), string(result))
	return string(result)
}

func ReadName(ctx *ParseContext) string {
	debug("ReadName Enter: %x\n", ctx.Offset())
	chunkOffset := int(ctx.ConsumeUint32())
	debug("chunkOffset %x ctx offset %x\n", chunkOffset, ctx.Offset())

	// Strings may be interned by reusing the location of the
	// string elsewhere in the chunk.
	if chunkOffset != ctx.Offset() {
		temp_ctx := ctx.Copy()
		temp_ctx.SetOffset(chunkOffset)

		temp_ctx.SkipBytes(4 + 2)
		return ReadPrefixedUnicodeString(temp_ctx, true)
	}

	ctx.SkipBytes(4 + 2)
	return ReadPrefixedUnicodeString(ctx, true)
}

// This is called when we open a new XML Tag. e.g. "<EventData".
func ParseOpenStartElement(ctx *ParseContext, has_attr bool) bool {
	debug("ParseOpenStartElement Enter: %x\n", ctx.Offset())
	/*
		dependencyID := ctx.ConsumeUint16()
		elementLength := ctx.ConsumeUint32()
	*/
	ctx.SkipBytes(2 + 4)
	nameBuffer := ReadName(ctx)

	attributeListLength := uint32(0)
	if has_attr {
		attributeListLength = ctx.ConsumeUint32()
	}

	debug("Start element %v with %v attributes\n", nameBuffer, attributeListLength)

	new_template := NewTemplate(0)
	ctx.PushTemplate(nameBuffer, new_template)

	return true
}

// Represents a close of the start element ('>' in <Element>)
func ParseCloseStartElement(ctx *ParseContext) bool {
	debug("ParseCloseStartElement %x\n", ctx.Offset())
	ctx.attribute_mode = false
	ctx.CurrentTemplate().CurrentKey = ""

	return true
}

// Represents a closing element (i.e. </Element>)
func ParseCloseElement(ctx *ParseContext) bool {
	debug("ParseCloseElement %x\n", ctx.Offset())
	ctx.PopTemplate()
	return true
}

func ParseValueText(ctx *ParseContext) bool {
	debug("ParseValueText %x\n", ctx.Offset())
	string_type := ctx.ConsumeUint8()
	string_value := ReadPrefixedUnicodeString(ctx, false)

	debug("ParseValueText Value is %v (type %v)\n",
		string_value, string_type)

	key := ctx.CurrentKey()
	ctx.CurrentTemplate().SetLiteral(key, string_value)
	ctx.attribute_mode = false

	return true
}

func ParseAttributes(ctx *ParseContext) bool {
	debug("ParseAttributes %x\n", ctx.Offset())
	attribute := ReadName(ctx)

	debug("Attribute is %v\n", attribute)
	ctx.CurrentTemplate().CurrentKey = attribute
	ctx.attribute_mode = true

	return true
}

// ParseTemplateInstance : le modèle est identifié par sa position de
// définition dans le chunk. Défini sur place, il est lu à la suite ; sinon il
// est relu à sa position s'il n'a pas encore été vu.
func ParseTemplateInstance(ctx *ParseContext) bool {
	debug("ParseTemplateInstance Enter %x\n", ctx.Offset())
	if ctx.ConsumeUint8() != 0x01 {
		return false
	}

	ctx.SkipBytes(4) // identifiant court du modèle
	defOffset := int(ctx.ConsumeUint32())
	if *ctx.bad {
		return false
	}

	template, pres := ctx.GetTemplateByID(defOffset)
	if defOffset == ctx.Offset() {
		// Définition sur place : suivant (4), GUID (16), taille (4), corps.
		ctx.SkipBytes(4 + 16)
		templateBodyLen := int(ctx.ConsumeUint32())
		if !pres {
			tmp_ctx := ctx.Copy()
			template = tmp_ctx.NewTemplate(defOffset)
			ParseBinXML(tmp_ctx)
		}
		ctx.SkipBytes(templateBodyLen)
	} else if !pres {
		tmp_ctx := ctx.Copy()
		tmp_ctx.SetOffset(defOffset)
		tmp_ctx.SkipBytes(4 + 16 + 4)
		template = tmp_ctx.NewTemplate(defOffset)
		ParseBinXML(tmp_ctx)
	}

	numArguments := int(ctx.ConsumeUint32())
	if *ctx.bad || numArguments < 0 || numArguments > (len(ctx.buff)-ctx.Offset())/4 {
		*ctx.bad = true
		return false
	}

	debug("ParseTemplateInstance Parse %x args @ %x\n", numArguments, ctx.Offset())

	type arg_detail struct {
		argLen  int
		argType uint16
	}
	args := make([]arg_detail, 0, numArguments)
	for i := 0; i < numArguments; i++ {
		argLen := ctx.ConsumeUint16()
		argType := ctx.ConsumeUint16()
		args = append(args, arg_detail{int(argLen), argType})
	}

	arg_values := make(map[int]interface{})

	for idx, arg := range args {
		if *ctx.bad {
			return false
		}
		if arg.argType == 0x21 { // BinXml
			new_ctx := ctx.Copy()
			ParseBinXML(new_ctx)
			ctx.SkipBytes(arg.argLen)
			arg_values[idx] = new_ctx.CurrentTemplate().Expand(nil)
			continue
		}
		raw := ctx.ConsumeBytes(arg.argLen)
		if raw == nil && arg.argLen > 0 {
			return false
		}
		if v := DecodeValue(arg.argType, raw); v != nil {
			arg_values[idx] = v
		}
		debug("%v Arg type %x len %x - %v\n",
			idx, arg.argType, arg.argLen, arg_values[idx])
	}

	debug("ParseTemplateInstance Exit %x\n", ctx.offset)
	expanded := template.Expand(arg_values)

	NormalizeEventData(expanded)

	ctx.CurrentTemplate().SetLiteral(ctx.CurrentKey(), expanded)

	return true
}

// DecodeValue convertit une valeur de substitution selon son type BinXML.
// La taille vient de l'enregistrement : une taille incohérente avec le type
// donne la valeur brute (Binary). nil signifie valeur absente.
func DecodeValue(argType uint16, raw []byte) interface{} {
	le := binary.LittleEndian
	n := len(raw)
	switch argType {
	case 0x00: // Null
		return nil
	case 0x01: // String UTF-16
		return string(UTF16LEToUTF8(raw))
	case 0x02: // AnsiString
		return strings.TrimRight(string(raw), "\x00")
	case 0x03: // Int8
		if n == 1 {
			return int8(raw[0])
		}
	case 0x04: // UInt8
		if n == 1 {
			return raw[0]
		}
	case 0x05: // Int16
		if n == 2 {
			return int16(le.Uint16(raw))
		}
	case 0x06: // UInt16
		if n == 2 {
			return le.Uint16(raw)
		}
	case 0x07: // Int32 (ex. MessageNumber des événements 4104, E4)
		if n == 4 {
			return int32(le.Uint32(raw))
		}
	case 0x08: // UInt32
		if n == 4 {
			return le.Uint32(raw)
		}
	case 0x09: // Int64
		if n == 8 {
			return int64(le.Uint64(raw))
		}
	case 0x0A: // UInt64
		if n == 8 {
			return le.Uint64(raw)
		}
	case 0x0B: // Real32
		if n == 4 {
			return math.Float32frombits(le.Uint32(raw))
		}
	case 0x0C: // Real64
		if n == 8 {
			return math.Float64frombits(le.Uint64(raw))
		}
	case 0x0D: // Bool
		for _, b := range raw {
			if b != 0 {
				return true
			}
		}
		return false
	case 0x0E: // Binary
		return Binary(raw)
	case 0x0F: // GUID
		if n == 16 {
			g := GUID{}
			_ = binary.Read(bytes.NewReader(raw), le, &g)
			return g
		}
	case 0x10: // SizeT, rendu en hexadécimal par Windows
		switch n {
		case 4:
			return HexInt64(le.Uint32(raw))
		case 8:
			return HexInt64(le.Uint64(raw))
		}
	case 0x11: // FileTime
		if n == 8 {
			return FileTime(le.Uint64(raw))
		}
	case 0x12: // SystemTime
		if n == 16 {
			u := func(i int) int { return int(le.Uint16(raw[2*i:])) }
			return SystemTime(time.Date(u(0), time.Month(u(1)), u(3), u(4), u(5), u(6), u(7)*1e6, time.UTC))
		}
	case 0x13: // SID
		if n >= 8 && n == 8+4*int(raw[1]) {
			v := uint64(0)
			for _, b := range raw[2:8] {
				v = v<<8 | uint64(b)
			}
			s := fmt.Sprintf("S-%d-%d", raw[0], v)
			for i := 8; i < n; i += 4 {
				s += fmt.Sprintf("-%d", le.Uint32(raw[i:]))
			}
			return SID(s)
		}
	case 0x14: // HexInt32 (E3)
		if n == 4 {
			return HexInt32(le.Uint32(raw))
		}
	case 0x15: // HexInt64 (E3)
		if n == 8 {
			return HexInt64(le.Uint64(raw))
		}
	case 0x81: // Tableau de chaînes UTF-16
		parts := strings.Split(string(UTF16LEToUTF8(raw)), "\x00")
		for len(parts) > 0 && parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
		return parts
	}
	// shortcut: autres types (tableaux 0x8x, EvtHandle…) rendus en binaire ; décoder s'ils apparaissent dans les journaux de référence.
	return Binary(raw)
}

func ParseOptionalSubstitution(ctx *ParseContext) bool {
	debug("ParseOptionalSubstitution Enter %x\n", ctx.Offset())
	substitutionID := ctx.ConsumeUint16()
	valueType := ctx.ConsumeUint8()
	if valueType == 0 {
		valueType = ctx.ConsumeUint8()
	}

	key := ctx.CurrentKey()
	ctx.CurrentTemplate().SetExpansion(key,
		uint32(substitutionID), uint32(valueType))

	return true
}

func ParseBinXML(ctx *ParseContext) {
	debug("ParseBinXML\n")
	if ctx.depth > maxDepth {
		*ctx.bad = true
		return
	}
	keep_going := true

	for keep_going && !*ctx.bad {
		tag := ctx.ConsumeUint8()
		debug("Tag %x @ %x\n", tag, ctx.Offset())
		switch tag {
		case 0x00 /* EOF */ :
			keep_going = false

		case 0x01 /* OpenStartElementToken */ :
			keep_going = ParseOpenStartElement(ctx, false)
		case 0x41:
			keep_going = ParseOpenStartElement(ctx, true)
		case 0x02: /* CloseStartElementToken */
			keep_going = ParseCloseStartElement(ctx)
		case 0x03 /*  CloseEmptyElementToken */, 0x04: /*  CloseElementToken */
			keep_going = ParseCloseElement(ctx)
		case 0x05 /*  ValueTextToken */, 0x45:
			keep_going = ParseValueText(ctx)
		case 0x06 /*  AttributeToken */, 0x46:
			keep_going = ParseAttributes(ctx)
		case 0x07 /* CDATASectionToken */, 0x47:
		case 0x08 /* CharRefToken */, 0x48:
		case 0x09 /*  EntityRefToken */, 0x49:
		case 0x0A /*  PITargetToken */ :
		case 0x0B /*  PIDataToken */ :
		case 0x0C /*  TemplateInstanceToken */ :
			keep_going = ParseTemplateInstance(ctx)
		case 0x0D /*  NormalSubstitutionToken */, 0x0E: /*  OptionalSubstitutionToken */
			keep_going = ParseOptionalSubstitution(ctx)

		case 0x0F /*  FragmentHeaderToken */ :
			ctx.SkipBytes(3)

		default:
			keep_going = false
		}
	}
}

func is_supported(minor, major uint16) bool {
	switch major {
	case 3:
		switch minor {
		case 0, 1, 2:
			return true
		}
	}
	return false
}

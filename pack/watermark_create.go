package pack

import "encoding/json"

func createWatermarked(kind, input, destination string, p Payload, public []byte, prepare func(source, string) (source, []watermarkIndexEntry, error)) error {
	original, e := inspect(kind, "app", input)
	if e != nil {
		return e
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return e
	}
	code, entries, e := prepare(original, tag)
	if e != nil {
		return e
	}
	code.file.Path = cipherName(0)
	private, e := json.Marshal(watermarkIndex{V: "1", Tag: tag, Files: []watermarkIndexFile{{Index: "0", Entries: entries}}})
	if e != nil || len(private) > watermarkIndexMax {
		return errInvalid
	}
	meta := source{file: File{Name: watermarkIndexName, Kind: "watermark", Path: cipherName(1), Size: int64(len(private)), Encoding: "raw", ChunkSize: ChunkSize}, generated: private}
	p.V = 2
	p, key, e := NewPayload(p, Manifest{Files: []File{code.file, meta.file}}, public)
	if e != nil {
		return e
	}
	defer clear(key)
	return publish(destination, []source{code, meta}, p, key)
}

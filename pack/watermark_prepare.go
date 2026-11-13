package pack

import (
	"encoding/json"
	"errors"
	"strconv"
)

func prepareWatermarkSources(inputs []source, public []byte) ([]source, error) {
	if len(inputs) == 0 || len(inputs) >= 65535 {
		return nil, errors.New("invalid watermark source count")
	}
	tag, e := watermarkPublicTag(public)
	if e != nil {
		return nil, e
	}
	index := watermarkIndex{V: "1", Tag: tag, Files: []watermarkIndexFile{}}
	sources := make([]source, 0, len(inputs)+1)
	entryCount, offsetCount := 0, 0
	for i, input := range inputs {
		if input.file.Name == watermarkIndexName {
			return nil, errors.New("reserved watermark content name")
		}
		var code source
		var entries []watermarkIndexEntry
		switch input.file.Kind {
		case "protect":
			prepared, err := prepareNativeWatermark(input, public)
			if err != nil {
				return nil, err
			}
			code = prepared[0]
			var local watermarkIndex
			if json.Unmarshal(prepared[1].generated, &local) != nil {
				return nil, invalid
			}
			entries = local.Files[0].Entries
		case "node":
			code, entries, e = prepareNodeWatermark(input, tag)
		case "python":
			code, entries, e = preparePythonWatermark(input, tag)
		case "php":
			code, entries, e = preparePHPWatermark(input, tag)
		case "java":
			code, entries, e = prepareJavaWatermark(input, tag)
		case "dotnet":
			code, entries, e = prepareDotnetWatermark(input, tag)
		default:
			return nil, errors.New("unsupported watermark code kind")
		}
		if e != nil {
			return nil, e
		}
		count := 0
		for _, entry := range entries {
			entryCount++
			offsetCount += len(entry.Offsets)
			count += len(entry.Offsets)
		}
		if count < 8 || entryCount > 65535 || offsetCount > 65535 {
			return nil, errors.New("watermark index slot/count limit")
		}
		code.file.Path = cipherName(i)
		sources = append(sources, code)
		index.Files = append(index.Files, watermarkIndexFile{Index: strconv.Itoa(i), Entries: entries})
	}
	private, e := json.Marshal(index)
	if e != nil || len(private) > watermarkIndexMax {
		return nil, errors.New("watermark index too large")
	}
	sources = append(sources, source{file: File{Name: watermarkIndexName, Kind: "watermark", Path: cipherName(len(sources)), Size: int64(len(private)), Encoding: "raw", ChunkSize: ChunkSize}, generated: private})
	return sources, nil
}

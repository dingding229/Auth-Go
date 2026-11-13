package pack

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPHPWatermarkRootDefinitionIsRepeatableAndWatermarkScoped(t *testing.T) {
	tag := strings.Repeat("a", 32)
	block, offsets, e := phpSlotBlock(tag, false)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(block, []byte("\\hash('sha256', $values[0])")) || !bytes.Contains(block, []byte("if (!\\defined($name))")) || !bytes.Contains(block, []byte("\\define($name, $values)")) {
		t.Fatal("root constant collides across repeated require or license changes")
	}
	if len(offsets) != 8 {
		t.Fatal("missing root VM literals")
	}
	for _, at := range offsets {
		if !bytes.Equal(block[at:at+96], []byte(tag+strings.Repeat("0", 64))) {
			t.Fatal("wrong root literal offset")
		}
	}
	static, statics, e := phpSlotBlock(tag, true)
	if e != nil || len(statics) != 8 || !bytes.Contains(static, []byte("static $__authgo_watermark_")) {
		t.Fatal("function static placement changed", e)
	}
}

func TestPHPWatermarkRecognizesOnlyFunctionDeclarations(t *testing.T) {
	cases := []struct {
		source string
		count  int
	}{
		{"<?php function pick(){return null;} $function=pick() ?? new class {};", 1},
		{"<?php $function=pick() ?? new class {};", 0},
		{"<?php namespace Foo\\function; $function = null;", 0},
		{"<?php $o->function(); if(true){} C::function(); if(true){} $o?->function();", 0},
		{"<?php class C{public function function(){return 1;}}", 1},
		{"<?php use function Foo\\function; if(true){}", 0},
		{"<?php function &a(){} function outer(){function inner(){} return function(){};}", 4},
		{"<?php $f=static function($x)use($n):array{return[];}; $g=fn($n)=>$n;", 1},
		{"<?php $s='function fake(){}'; /* function fake(){} */ $function = new class {};", 0},
	}
	for _, item := range cases {
		file, e := os.CreateTemp(t.TempDir(), "core-*.php")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = file.WriteString(item.source); e != nil {
			t.Fatal(e)
		}
		positions, e := phpFunctionInsertions(file, int64(len(item.source)))
		file.Close()
		if e != nil || len(positions) != item.count {
			t.Fatalf("%q positions=%v want=%d error=%v", item.source, positions, item.count, e)
		}
		for _, at := range positions {
			if at < 1 || item.source[at-1] != '{' {
				t.Fatal("not a function body")
			}
		}
	}
}

func TestPHPFunctionSlotLivesInPrivateClosureNotCallerLocals(t *testing.T) {
	block, offsets, e := phpSlotBlock(strings.Repeat("a", 32), true)
	if e != nil || len(offsets) != 8 {
		t.Fatal(e)
	}
	if !bytes.HasPrefix(block, []byte(" (static function() { static $__authgo_watermark_")) || !bytes.HasSuffix(block, []byte("; })();")) {
		t.Fatal("watermark local can leak into caller get_defined_vars")
	}
	for _, at := range offsets {
		if !bytes.Equal(block[at:at+96], []byte(strings.Repeat("a", 32)+strings.Repeat("0", 64))) {
			t.Fatal("wrong function literal offset")
		}
	}
}

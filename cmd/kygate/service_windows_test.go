package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestTaskXML(t *testing.T) {
	cfg := &serviceConfig{Name: "KyGate", Exe: `C:\Program Files\KyGate & co\kygate.exe`, DataDir: `C:\Users\dev\.kygate`}
	doc := taskXML(cfg, `PC\dev`)
	var task struct {
		Command   string `xml:"Actions>Exec>Command"`
		Arguments string `xml:"Actions>Exec>Arguments"`
		UserID    string `xml:"Triggers>LogonTrigger>UserId"`
		Limit     string `xml:"Settings>ExecutionTimeLimit"`
		RunLevel  string `xml:"Principals>Principal>RunLevel"`
	}
	// The declaration says UTF-16, which registerService writes; parse the body.
	body := doc[strings.Index(doc, "<Task"):]
	if err := xml.Unmarshal([]byte(body), &task); err != nil {
		t.Fatal(err)
	}
	if task.Command != cfg.Exe || task.Arguments != `service run --data-dir "C:\Users\dev\.kygate"` || task.UserID != `PC\dev` {
		t.Fatalf("%+v", task)
	}
	if task.Limit != "PT0S" || task.RunLevel != "LeastPrivilege" {
		t.Fatalf("the task must run without a time limit and without elevation: %+v", task)
	}
}

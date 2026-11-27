package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCategoriesTable(t *testing.T) {
	cats, err := loadCategories(categoriesJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 16 {
		t.Errorf("%d categories, want 16", len(cats))
	}
	names := map[string]bool{}
	n := 0
	for c, srcs := range cats {
		for _, s := range srcs {
			n++
			if names[s.Name] {
				t.Errorf("duplicate source %s", s.Name)
			}
			names[s.Name] = true
			if len(s.EventIDs) == 0 || s.Channel == "" || s.Label == "" {
				t.Errorf("%s/%s: incomplete source %+v", c, s.Name, s)
			}
		}
	}
	if n != 17 {
		t.Errorf("%d sources, want 17", n)
	}
	p := cats["process_creation"]
	if len(p) != 2 || p[1].Name != "security-4688" || p[1].Label != "Security 4688" || p[1].Fields == nil ||
		p[1].Rename["Image"] != "NewProcessName" || p[1].Rename["ParentImage"] != "ParentProcessName" ||
		!p[1].Fields["CommandLine"] || len(p[1].Fields) != 3 || p[0].Fields != nil || p[0].Rename != nil {
		t.Errorf("process_creation sources: %+v %+v", p[0], p[1])
	}
	if d := cats["registry_delete"][0]; !d.EventType["deletekey"] || !d.EventType["deletevalue"] || len(d.EventType) != 2 {
		t.Errorf("registry_delete: %+v", d)
	}
	sum := sha256.Sum256(categoriesJSON)
	if CategoriesVersion != hex.EncodeToString(sum[:8]) {
		t.Errorf("version %s", CategoriesVersion)
	}

	// Tables invalides : rejetées avec une cause.
	src := string(categoriesJSON)
	for name, bad := range map[string]string{
		"duplicate category": strings.Replace(src, `"category": "driver_load"`, `"category": "image_load"`, 1),
		"duplicate source":   strings.Replace(src, `"name": "sysmon-6"`, `"name": "sysmon-7"`, 1),
		"no event id": strings.Replace(src, `"event_ids": [
          6
        ]`, `"event_ids": []`, 1),
		"rename outside fields": strings.Replace(src, `"ParentImage"
        ]`, `"Other"
        ]`, 1),
		"unknown key": strings.Replace(src, `"name": "sysmon-6"`, `"nom": "x", "name": "sysmon-6"`, 1),
	} {
		if bad == src {
			t.Fatalf("%s: test table not modified", name)
		}
		if _, err := loadCategories([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCategoryRules : une règle par catégorie n'est évaluée que sur les
// événements de ses sources (FR-001, FR-002, SC-001).
func TestCategoryRules(t *testing.T) {
	det := "  sel:\n    Marker: x\n  condition: sel\n"
	for c, srcs := range categories {
		s := srcs[0]
		rs := mustLoad(t, writeRules(t, map[string]string{"r.yml": catRule("  category: "+c+"\n", det)}))
		if len(rs.Applied) != 1 {
			t.Fatalf("%s: not applied", c)
		}
		r := rs.Applied[0]
		var id uint32
		for i := range s.EventIDs {
			if id == 0 || i < id {
				id = i
			}
		}
		md := func() map[string]string {
			m := map[string]string{"Marker": "x"}
			for v := range s.EventType {
				m["EventType"] = strings.ToUpper(v) // comparé sans tenir compte de la casse
				break
			}
			return m
		}
		if !matches(rs, r, evtx(s.Channel, "P", id, md(), 1)) {
			t.Errorf("%s: positive event %s/%d not detected", c, s.Channel, id)
		}
		if matches(rs, r, evtx(s.Channel, "P", 9999, md(), 2)) {
			t.Errorf("%s: other event id detected", c)
		}
		if matches(rs, r, evtx("Application", "P", id, md(), 3)) {
			t.Errorf("%s: other channel detected", c)
		}
	}

	load := func(c string) (*Ruleset, *Rule) {
		rs := mustLoad(t, writeRules(t, map[string]string{"r.yml": catRule("  category: "+c+"\n", det)}))
		return rs, rs.Applied[0]
	}
	mark := func(md map[string]string) map[string]string { md["Marker"] = "x"; return md }
	rs, r := load("network_connection")
	if matches(rs, r, evtx(sysmonCh, "P", 1, mark(map[string]string{}), 1)) {
		t.Error("network_connection rule evaluated on a process creation event")
	}
	rs, r = load("registry_add")
	if matches(rs, r, evtx(sysmonCh, "P", 12, mark(map[string]string{"EventType": "DeleteKey"}), 1)) ||
		matches(rs, r, evtx(sysmonCh, "P", 12, mark(map[string]string{}), 2)) ||
		!matches(rs, r, evtx(sysmonCh, "P", 12, mark(map[string]string{"EventType": "createkey"}), 3)) {
		t.Error("registry_add and EventType")
	}
	rs, r = load("registry_event")
	for _, id := range []uint32{12, 13, 14} {
		if !matches(rs, r, evtx(sysmonCh, "P", id, mark(map[string]string{"EventType": "Anything"}), int(id))) {
			t.Errorf("registry_event: %d not detected", id)
		}
	}
}

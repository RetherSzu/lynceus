package detection

import (
	"io/fs"
	"strings"
	"testing"

	"DFIRFlow/internal/normalizer"
)

// embeddedCases donne, pour chaque règle embarquée, au moins un positif et un
// négatif (constitution VI, research R7).
var embeddedCases = map[string]struct{ pos, neg []normalizer.Event }{
	"security_log_cleared.yml": {
		pos: []normalizer.Event{evtx("Security", "Microsoft-Windows-Eventlog", 1102, nil, 1)},
		neg: []normalizer.Event{
			evtx("Security", "Some-Other-Provider", 1102, nil, 2),
			evtx("System", "Microsoft-Windows-Eventlog", 1102, nil, 3),
			evtx("Security", "Microsoft-Windows-Eventlog", 1100, nil, 4),
		},
	},
	"system_log_cleared.yml": {
		pos: []normalizer.Event{evtx("System", "Microsoft-Windows-Eventlog", 104, nil, 1)},
		neg: []normalizer.Event{evtx("System", "Other", 104, nil, 2), evtx("Security", "Microsoft-Windows-Eventlog", 104, nil, 3)},
	},
	"audit_policy_changed.yml": {
		pos: []normalizer.Event{evtx("Security", "Microsoft-Windows-Security-Auditing", 4719, nil, 1)},
		neg: []normalizer.Event{evtx("Security", "Microsoft-Windows-Security-Auditing", 4720, nil, 2)},
	},
	"user_account_created.yml": {
		pos: []normalizer.Event{evtx("Security", "Microsoft-Windows-Security-Auditing", 4720, map[string]string{"TargetUserName": "eve"}, 1)},
		neg: []normalizer.Event{evtx("Security", "Microsoft-Windows-Security-Auditing", 4726, nil, 2)},
	},
	"privileged_group_member_added.yml": {
		pos: []normalizer.Event{
			evtx("Security", "Microsoft-Windows-Security-Auditing", 4732, map[string]string{"TargetSid": "S-1-5-32-544"}, 1),
			evtx("Security", "Microsoft-Windows-Security-Auditing", 4728, map[string]string{"TargetSid": "S-1-5-21-1-2-3-512"}, 2),
			evtx("Security", "Microsoft-Windows-Security-Auditing", 4756, map[string]string{"TargetSid": "S-1-5-21-1-2-3-519"}, 3),
		},
		neg: []normalizer.Event{
			evtx("Security", "Microsoft-Windows-Security-Auditing", 4732, map[string]string{"TargetSid": "S-1-5-32-545"}, 4),
			evtx("Security", "Microsoft-Windows-Security-Auditing", 4728, map[string]string{"TargetSid": "S-1-5-21-1-2-3-513"}, 5),
			evtx("Security", "Microsoft-Windows-Security-Auditing", 4624, map[string]string{"TargetSid": "S-1-5-32-544"}, 6),
		},
	},
	"service_installed.yml": {
		pos: []normalizer.Event{evtx("System", "Service Control Manager", 7045, map[string]string{"ServiceName": "x"}, 1)},
		neg: []normalizer.Event{evtx("System", "Other", 7045, nil, 2), evtx("System", "Service Control Manager", 7036, nil, 3)},
	},
	"scheduled_task_created.yml": {
		pos: []normalizer.Event{evtx("Security", "Microsoft-Windows-Security-Auditing", 4698, nil, 1)},
		neg: []normalizer.Event{evtx("Security", "Microsoft-Windows-Security-Auditing", 4699, nil, 2)},
	},
}

func TestEmbeddedRules(t *testing.T) {
	rs, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Applied) != 7 || rs.Skipped != 0 || len(rs.Refused) != 0 || rs.Source != Embedded || len(rs.Version) != 16 {
		t.Fatalf("embedded set: %d applied, %d skipped, %v refused, source %s", len(rs.Applied), rs.Skipped, rs.Refused, rs.Source)
	}
	want := map[string][2]string{ // fichier -> id, technique (data-model.md)
		"security_log_cleared.yml":          {"8ad87a09-d977-4445-9e5a-962e9023846b", "T1070.001"},
		"system_log_cleared.yml":            {"7f021602-7eb2-46cc-bd9c-8791ff6b80c6", "T1070.001"},
		"audit_policy_changed.yml":          {"16e98cfe-8ffe-44bc-8353-804570a5f7b3", "T1562.002"},
		"user_account_created.yml":          {"92be069d-0b8f-4ecd-a4c3-236eb494fa35", "T1136.001"},
		"privileged_group_member_added.yml": {"c45e29cd-cdb3-495e-9bb4-596a96da98bb", "T1098"},
		"service_installed.yml":             {"937be0a0-b743-4102-83e6-25f8c5eed60b", "T1543.003"},
		"scheduled_task_created.yml":        {"5f1c65f2-02d2-4919-abcd-8f4b6066b681", "T1053.005"},
	}
	names, _ := fs.Glob(embedded, "rules/*.yml")
	if len(names) != len(embeddedCases) {
		t.Errorf("%d embedded rules, %d with test cases", len(names), len(embeddedCases))
	}
	for _, r := range rs.Applied {
		name := strings.TrimPrefix(r.File, "embedded:")
		if w := want[name]; r.ID != w[0] || r.MITRE != w[1] {
			t.Errorf("%s: id %s mitre %s, want %v", name, r.ID, r.MITRE, w)
		}
		c, ok := embeddedCases[name]
		if !ok || len(c.pos) == 0 || len(c.neg) == 0 {
			t.Errorf("%s: missing positive or negative case", name)
			continue
		}
		for _, ev := range c.pos {
			if !matches(rs, r, ev) {
				t.Errorf("%s: positive event %d not detected", name, *ev.EventID)
			}
		}
		for _, ev := range c.neg {
			if matches(rs, r, ev) {
				t.Errorf("%s: negative event %d (%s, %v) detected", name, *ev.EventID, ev.Channel, ev.Metadata)
			}
		}
	}
}

// matches applique r comme Run : seulement aux événements de son canal.
func matches(rs *Ruleset, r *Rule, ev normalizer.Event) bool {
	for _, x := range rs.byChannel[strings.ToLower(ev.Channel)] {
		if x == r {
			return r.match(&ev)
		}
	}
	return false
}

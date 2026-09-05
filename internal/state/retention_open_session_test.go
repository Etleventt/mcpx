package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionDeletesExpiredEventsFromOpenSessions(t *testing.T) {
	db, service, now := newRetentionTestService(t, "")
	insertRetentionPrincipal(t, db, "principal")
	statuses := []string{"active", "idle", "blocked"}
	var sequences []int64
	for _, status := range statuses {
		insertRetentionSession(t, db, status, "demo", status, "principal")
		sequences = append(sequences, insertRetentionEvent(t, db, "demo", status, "command.output", "command_run", now.Add(-2*time.Hour).UnixMilli()))
	}
	recent := insertRetentionEvent(t, db, "demo", "active", "command.output", "command_run", now.Add(-10*time.Minute).UnixMilli())
	report, err := service.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.DeletedObservationEvents != len(sequences) {
		t.Fatalf("deleted=%d want=%d report=%+v", report.DeletedObservationEvents, len(sequences), report)
	}
	for _, sequence := range sequences {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM observation_events WHERE sequence = ?`, sequence).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("expired event %d from open session remains", sequence)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observation_events WHERE sequence = ?`, recent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("recent open-session event was deleted")
	}
}

func TestRetentionDeletesFinishedTasksFromOpenSessionsAndKeepsEvidence(t *testing.T) {
	logDir := t.TempDir()
	db, service, now := newRetentionTestService(t, logDir)
	insertRetentionPrincipal(t, db, "principal")
	insertRetentionSession(t, db, "active", "demo", "active", "principal")
	old := now.Add(-2 * time.Hour).UnixMilli()
	writeLogs := func(id string) string {
		path := filepath.Join(logDir, id+".log")
		for _, candidate := range []string{path, filepath.Join(logDir, id+".stdout.log"), filepath.Join(logDir, id+".stderr.log")} {
			if err := os.WriteFile(candidate, []byte(id), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	finishedPath := writeLogs("finished")
	protectedPath := writeLogs("protected")
	runningPath := writeLogs("running")
	_, err := db.Exec(`INSERT INTO terminal_tasks
		(id, remote_session_id, workspace_name, workspace_path, command, status, log_path, started_at, finished_at, updated_at)
		VALUES
		('finished', 'active', 'demo', '/tmp', 'echo finished', 'exited', ?, ?, ?, ?),
		('protected', 'active', 'demo', '/tmp', 'echo protected', 'exited', ?, ?, ?, ?),
		('running', 'active', 'demo', '/tmp', 'echo running', 'running', ?, ?, NULL, ?)`,
		finishedPath, old, old, old,
		protectedPath, old, old, old,
		runningPath, old, old)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO plans(id, remote_session_id, goal, summary, status, version, created_by, created_at, updated_at)
		VALUES ('plan', 'active', 'goal', '', 'in_progress', 1, 'principal', ?, ?);
		INSERT INTO plan_tasks(id, plan_id, ordinal, title, description, status, depends_on_json, created_at, updated_at)
		VALUES ('plan-task', 'plan', 0, 'task', '', 'in_progress', '[]', ?, ?);
		INSERT INTO plan_task_evidence(id, plan_id, task_id, kind, reference_id, metadata_json, created_by, created_at)
		VALUES ('evidence', 'plan', 'plan-task', 'execution_task', 'protected', '{}', 'principal', ?)`, old, old, old, old, old)
	if err != nil {
		t.Fatal(err)
	}
	report, err := service.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.DeletedTerminalTasks != 1 {
		t.Fatalf("deleted tasks=%d report=%+v", report.DeletedTerminalTasks, report)
	}
	for _, id := range []string{"protected", "running"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM terminal_tasks WHERE id = ?`, id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("protected task %q was deleted", id)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM terminal_tasks WHERE id = 'finished'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("finished task in active session remains")
	}
	for _, suffix := range []string{".log", ".stdout.log", ".stderr.log"} {
		if _, err := os.Stat(filepath.Join(logDir, "finished"+suffix)); !os.IsNotExist(err) {
			t.Fatalf("finished sidecar remains: %s err=%v", suffix, err)
		}
		if _, err := os.Stat(filepath.Join(logDir, "protected"+suffix)); err != nil {
			t.Fatalf("protected log missing: %s err=%v", suffix, err)
		}
	}
}

package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// These tables contain durable user data. Runtime sessions, jobs and one-time
// challenges are intentionally excluded from backups and recreated empty.
var backupTables = []string{
	"settings",
	"accounts",
	"logs",
	"traffic_hourly",
	"traffic_daily",
	"billing_cache",
	"instance_traffic_usage",
	"passkey_credentials",
}

// Snapshot creates a consistent SQLite snapshot even while WAL mode is active.
func (s *Store) Snapshot(path string) error {
	if path == "" {
		return fmt.Errorf("snapshot path is empty")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove old snapshot: %w", err)
	}
	if _, err := s.DB.Exec(`VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("create database snapshot: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("protect database snapshot: %w", err)
	}
	return nil
}

// RestoreSnapshot replaces durable rows in the current database without
// replacing the open SQLite file. This keeps the running server consistent and
// lets the caller invalidate sessions in the same transaction.
func (s *Store) RestoreSnapshot(path string, encryptionKey [32]byte) error {
	if path == "" {
		return fmt.Errorf("snapshot path is empty")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("snapshot is unavailable: %w", err)
	}

	source, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open restore snapshot: %w", err)
	}
	source.SetMaxOpenConns(1)
	defer source.Close()
	var integrity string
	if err := source.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		if err == nil {
			err = fmt.Errorf("integrity check returned %q", integrity)
		}
		return fmt.Errorf("invalid restore snapshot: %w", err)
	}
	for _, table := range backupTables {
		var count int
		if err := source.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			if err == nil {
				err = fmt.Errorf("table %s is missing", table)
			}
			return fmt.Errorf("unsupported restore snapshot: %w", err)
		}
	}

	// Older snapshots may omit this table. Its names are needed to identify
	// legacy custom records during the DNS migration.
	var hasDNSNames int
	if err := source.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='dns_names'`).Scan(&hasDNSNames); err != nil {
		return fmt.Errorf("check legacy DNS names: %w", err)
	}

	s.DNSConfigMu.Lock()
	defer s.DNSConfigMu.Unlock()
	if _, err := s.DB.Exec(`ATTACH DATABASE ? AS restore_source`, path); err != nil {
		return fmt.Errorf("attach restore snapshot: %w", err)
	}
	detached := false
	defer func() {
		if !detached {
			_, _ = s.DB.Exec(`DETACH DATABASE restore_source`)
		}
	}()

	tx, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin restore: %w", err)
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return fmt.Errorf("restore database: %w", cause)
	}
	for _, table := range backupTables {
		if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
			return rollback(err)
		}
		columns, err := sharedColumns(tx, table)
		if err != nil {
			return rollback(err)
		}
		if _, err := tx.Exec(`INSERT INTO ` + table + `(` + columns + `) SELECT ` + columns + ` FROM restore_source.` + table); err != nil {
			return rollback(err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM dns_names`); err != nil {
		return rollback(err)
	}
	if hasDNSNames != 0 {
		if _, err := tx.Exec(`INSERT INTO dns_names(instance_key,name) SELECT instance_key,name FROM restore_source.dns_names`); err != nil {
			return rollback(err)
		}
	}
	// Never revive sessions or an in-flight operation from an old backup.
	for _, table := range []string{"sessions", "login_attempts", "passkey_challenges", "telegram_action_tokens", "jobs", "ecs_create_tasks", "telegram_bot_state"} {
		if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit restore: %w", err)
	}
	s.keyMu.Lock()
	s.Key = encryptionKey
	s.keyMu.Unlock()
	if _, err := s.DB.Exec(`DETACH DATABASE restore_source`); err != nil {
		return fmt.Errorf("detach restore snapshot: %w", err)
	}
	detached = true
	if err := s.restoreInstanceDNS(); err != nil {
		return err
	}
	return s.migrateDNSHosts()
}

// sharedColumns lists the columns a table has in both the live database and
// the attached snapshot. Copying by name lets a backup taken before a column
// was added restore cleanly (the column keeps its default), and stays correct
// when ALTER TABLE has placed columns in a different order than CREATE TABLE.
func sharedColumns(tx *sql.Tx, table string) (string, error) {
	rows, err := tx.Query(`SELECT live.name FROM pragma_table_info(?) AS live
		WHERE live.name IN (SELECT name FROM pragma_table_info(?, 'restore_source'))
		ORDER BY live.cid`, table, table)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return "", err
		}
		names = append(names, `"`+name+`"`)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", fmt.Errorf("table %s has no columns in common with the snapshot", table)
	}
	return strings.Join(names, ","), nil
}

// BackupTables returns a copy for manifest and compatibility checks outside the
// store package.
func BackupTables() []string {
	return append([]string(nil), backupTables...)
}

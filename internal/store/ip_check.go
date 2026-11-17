package store

import "time"

// IPCheck is the last mainland-China reachability result for one instance.
// Status is "ok", "blocked" or "unknown".
type IPCheck struct {
	AccountID int64
	IP        string
	Status    string
	Detail    string
	CheckedAt int64
}

// SaveIPCheck records the latest reachability result of an instance's IP.
func (s *Store) SaveIPCheck(check IPCheck) error {
	if check.CheckedAt == 0 {
		check.CheckedAt = time.Now().Unix()
	}
	_, err := s.DB.Exec(`INSERT INTO ip_checks(account_id,ip,status,detail,checked_at) VALUES(?,?,?,?,?)
		ON CONFLICT(account_id) DO UPDATE SET ip=excluded.ip,status=excluded.status,detail=excluded.detail,checked_at=excluded.checked_at`,
		check.AccountID, check.IP, check.Status, check.Detail, check.CheckedAt)
	return err
}

// IPChecks returns every stored result keyed by account ID.
func (s *Store) IPChecks() map[int64]IPCheck {
	result := map[int64]IPCheck{}
	rows, err := s.DB.Query(`SELECT account_id,ip,status,detail,checked_at FROM ip_checks`)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var check IPCheck
		if rows.Scan(&check.AccountID, &check.IP, &check.Status, &check.Detail, &check.CheckedAt) == nil {
			result[check.AccountID] = check
		}
	}
	return result
}

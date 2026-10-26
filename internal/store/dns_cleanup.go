package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
)

// DNSCleanupKind is the job kind that removes a dead instance's IP from DNS.
// The job's entity key is the IP, so at most one cleanup per IP is pending.
const DNSCleanupKind = "dns_cleanup"

// DNSCleanupPayload describes why an IP must leave DNS.
type DNSCleanupPayload struct {
	IP         string `json:"ip"`
	InstanceID string `json:"instanceId"`
	Label      string `json:"label"`
	Reason     string `json:"reason"` // expired | vanished | released | ip_replaced
}

// DNSCleanupReasonText is the user-facing explanation of a cleanup reason.
func DNSCleanupReasonText(reason string) string {
	switch reason {
	case "expired":
		return "包年包月实例已到期"
	case "vanished":
		return "实例已从阿里云消失（到期释放 / 抢占回收 / 控制台删除）"
	case "released":
		return "在本系统释放了实例"
	case "ip_replaced":
		return "更换了公网 IP，旧 IP 已归还阿里云"
	}
	return reason
}

// EnqueueDNSCleanup queues ip for removal from DNS when cleanup is switched on.
// It reports whether a new job was created.
func (s *Store) EnqueueDNSCleanup(ip, instanceID, label, reason string) (bool, error) {
	ip = strings.TrimSpace(ip)
	if s.GetSetting("dns_cleanup_enabled", "0") != "1" || net.ParseIP(ip).To4() == nil {
		return false, nil
	}
	var active int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM jobs WHERE kind=? AND entity_key=? AND status IN ('queued','running','retry')`, DNSCleanupKind, ip).Scan(&active); err != nil {
		return false, err
	}
	if active > 0 {
		return false, nil
	}
	payload := DNSCleanupPayload{IP: ip, InstanceID: instanceID, Label: label, Reason: reason}
	jobID := fmt.Sprintf("dns-cleanup-%s-%d", ip, time.Now().UnixNano())
	if err := s.EnqueueJob(jobID, DNSCleanupKind, ip, payload); err != nil {
		return false, err
	}
	s.AddLog("info", fmt.Sprintf("已加入解析清理队列 [%s] %s（%s）", label, ip, DNSCleanupReasonText(reason)))
	return true, nil
}

// JobRecord is a job as shown in history views.
type JobRecord struct {
	JobID     string
	Kind      string
	EntityKey string
	Status    string
	Payload   string
	Attempts  int
	LastError string
	Result    string
	CreatedAt int64
	UpdatedAt int64
}

const jobRecordColumns = `job_id,kind,entity_key,status,payload,attempts,COALESCE(last_error,''),COALESCE(result,''),created_at,updated_at`

func scanJobRecord(row interface{ Scan(...any) error }) (JobRecord, error) {
	var j JobRecord
	err := row.Scan(&j.JobID, &j.Kind, &j.EntityKey, &j.Status, &j.Payload, &j.Attempts, &j.LastError, &j.Result, &j.CreatedAt, &j.UpdatedAt)
	return j, err
}

// ListJobs returns the most recent jobs of one kind.
func (s *Store) ListJobs(kind string, limit int) ([]JobRecord, error) {
	rows, err := s.DB.Query(`SELECT `+jobRecordColumns+` FROM jobs WHERE kind=? ORDER BY id DESC LIMIT ?`, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]JobRecord, 0)
	for rows.Next() {
		job, err := scanJobRecord(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, job)
	}
	return result, rows.Err()
}

// JobRecordByID returns one job.
func (s *Store) JobRecordByID(jobID string) (*JobRecord, error) {
	job, err := scanJobRecord(s.DB.QueryRow(`SELECT `+jobRecordColumns+` FROM jobs WHERE job_id=?`, jobID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("任务不存在")
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// SetJobResult records a human-readable outcome for a finished job.
func (s *Store) SetJobResult(jobID, result string) error {
	_, err := s.DB.Exec(`UPDATE jobs SET result=?,updated_at=? WHERE job_id=?`, result, time.Now().Unix(), jobID)
	return err
}

// RequeueJob runs a finished or failed job again from the first attempt.
func (s *Store) RequeueJob(jobID string) error {
	job, err := s.JobRecordByID(jobID)
	if err != nil {
		return err
	}
	if job.Status == "queued" || job.Status == "running" || job.Status == "retry" {
		return fmt.Errorf("任务已在队列中")
	}
	var active int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM jobs WHERE kind=? AND entity_key=? AND status IN ('queued','running','retry')`, job.Kind, job.EntityKey).Scan(&active); err != nil {
		return err
	}
	if active > 0 {
		return fmt.Errorf("同一个 IP 已有排队中的清理任务")
	}
	now := time.Now().Unix()
	_, err = s.DB.Exec(`UPDATE jobs SET status='queued',attempts=0,available_at=?,locked_at=0,last_error='',result='',updated_at=? WHERE job_id=?`, now, now, jobID)
	return err
}

// InstanceExpiry is a prepaid instance's expiry and whether its IP was queued for cleanup.
type InstanceExpiry struct {
	InstanceID string
	ChargeType string
	ExpiredAt  int64
	QueuedAt   int64
}

// Expired reports whether a prepaid instance is past its expiry time.
func (e InstanceExpiry) Expired(now time.Time) bool {
	return e.ChargeType == "PrePaid" && e.ExpiredAt > 0 && e.ExpiredAt <= now.Unix()
}

// InstanceExpiry returns the stored expiry of an instance (zero value if unknown).
func (s *Store) InstanceExpiry(instanceID string) InstanceExpiry {
	e := InstanceExpiry{InstanceID: instanceID}
	_ = s.DB.QueryRow(`SELECT charge_type,expired_at,queued_at FROM instance_expiry WHERE instance_id=?`, instanceID).Scan(&e.ChargeType, &e.ExpiredAt, &e.QueuedAt)
	return e
}

// SaveInstanceExpiry stores an instance's charge type, expiry and queued marker.
func (s *Store) SaveInstanceExpiry(e InstanceExpiry) error {
	_, err := s.DB.Exec(`INSERT INTO instance_expiry(instance_id,charge_type,expired_at,queued_at,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(instance_id) DO UPDATE SET charge_type=excluded.charge_type,expired_at=excluded.expired_at,queued_at=excluded.queued_at,updated_at=excluded.updated_at`,
		e.InstanceID, e.ChargeType, e.ExpiredAt, e.QueuedAt, time.Now().Unix())
	return err
}

// ExpiryByInstance returns every stored expiry keyed by instance ID.
func (s *Store) ExpiryByInstance() map[string]InstanceExpiry {
	result := map[string]InstanceExpiry{}
	rows, err := s.DB.Query(`SELECT instance_id,charge_type,expired_at,queued_at FROM instance_expiry`)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var e InstanceExpiry
		if rows.Scan(&e.InstanceID, &e.ChargeType, &e.ExpiredAt, &e.QueuedAt) == nil {
			result[e.InstanceID] = e
		}
	}
	return result
}

// AccountPublicIP is the address DNS should point at: the EIP when one is bound.
func AccountPublicIP(account app.Account) string {
	if account.PublicIPMode == "eip" && account.EIPAddress != "" {
		return account.EIPAddress
	}
	if account.PublicIP != "" {
		return account.PublicIP
	}
	return account.EIPAddress
}

// EnqueueAccountDNSCleanup queues the account's current public IP for removal.
func (s *Store) EnqueueAccountDNSCleanup(account app.Account, reason string) (bool, error) {
	label := account.Remark
	if account.InstanceName != "" && account.InstanceName != label {
		if label != "" {
			label += " / "
		}
		label += account.InstanceName
	}
	if label == "" {
		label = account.InstanceID
	}
	return s.EnqueueDNSCleanup(AccountPublicIP(account), account.InstanceID, label, reason)
}

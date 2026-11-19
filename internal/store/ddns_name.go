package store

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/Kori1c/ecs-controller/internal/app"
)

// siteAWS mirrors cloud.SiteAWS; store cannot import the cloud package.
const siteAWS = "aws"

var (
	ddnsSlugPattern  = regexp.MustCompile(`[^a-z0-9]+`)
	dnsLabelPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	errDNSNameFormat = errors.New("解析名称只能包含字母、数字、短横线和点，每段不超过 63 个字符，且不能以短横线开头或结尾")
)

// dnsNameKey identifies an instance by the fields every DDNS cleanup payload
// carries, so a custom name can still be found after the row is deleted.
func dnsNameKey(account app.Account) string {
	return account.AccessKeyID + "|" + account.RegionID + "|" + account.InstanceID
}

// CustomDNSName is the name the user chose for the instance, or "".
func (s *Store) CustomDNSName(account app.Account) string {
	var name string
	_ = s.DB.QueryRow(`SELECT name FROM dns_names WHERE instance_key=?`, dnsNameKey(account)).Scan(&name)
	return name
}

// CustomDNSLabels includes explicitly assigned names even after an instance
// disappears. Cleanup must preserve those names on retry and after removal.
func (s *Store) CustomDNSLabels() ([]string, error) {
	rows, err := s.DB.Query(`SELECT DISTINCT name FROM dns_names WHERE name <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// SetCustomDNSName stores the instance's chosen name; "" goes back to the
// automatic one.
func (s *Store) SetCustomDNSName(account app.Account, name string) error {
	if name == "" {
		return s.DeleteCustomDNSName(account)
	}
	_, err := s.DB.Exec(`INSERT INTO dns_names(instance_key,name) VALUES(?,?) ON CONFLICT(instance_key) DO UPDATE SET name=excluded.name`, dnsNameKey(account), name)
	return err
}

// DeleteCustomDNSName forgets the instance's chosen name.
func (s *Store) DeleteCustomDNSName(account app.Account) error {
	_, err := s.DB.Exec(`DELETE FROM dns_names WHERE instance_key=?`, dnsNameKey(account))
	return err
}

// NormalizeDNSName validates a name typed for one instance. It accepts a
// bare label ("jp1"), several labels ("jp1.node") or the full name under the
// root domain, and returns it without the root domain. "" is allowed.
func NormalizeDNSName(name, domain string) (string, error) {
	name = strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	domain = NormalizeDDNSDomain(domain)
	if domain != "" {
		if name == domain {
			return "", errors.New("解析名称不能和根域名相同")
		}
		name = strings.TrimSuffix(name, "."+domain)
	}
	if name == "" {
		return "", nil
	}
	if len(name) > 200 {
		return "", errDNSNameFormat
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return "", errDNSNameFormat
		}
	}
	return name, nil
}

// DDNSNameForDomain reconstructs the name assigned by older versions so their
// standalone records can be removed during migration.
func (s *Store) DDNSNameForDomain(account app.Account, accounts []app.Account, custom, domain string) string {
	if custom != "" {
		return joinDomain(custom, domain)
	}
	return joinDomain(s.autoDDNSName(account, accounts), domain)
}

func joinDomain(name, domain string) string {
	if domain == "" {
		return name
	}
	return name + "." + domain
}

func (s *Store) autoDDNSName(account app.Account, accounts []app.Account) string {
	groupKey := account.GroupKey
	if groupKey == "" {
		groupKey = account.AccessKeyID + "|" + account.RegionID
	}
	count := 0
	for _, item := range accounts {
		key := item.GroupKey
		if key == "" {
			key = item.AccessKeyID + "|" + item.RegionID
		}
		if key == groupKey && item.InstanceID != "" && item.IsDeleted == 0 && item.CloudPresence != "missing" {
			count++
		}
	}
	base := ""
	if groups, err := s.LoadGroups(); err == nil {
		for _, group := range groups {
			if group.GroupKey == groupKey {
				base = group.Remark
				break
			}
		}
	}
	if base == "" {
		base = account.Remark
	}
	if base == "" {
		base = account.InstanceName
	}
	if base == "" {
		base = strings.TrimPrefix(account.InstanceID, "i-")
	}
	base = SlugDDNS(base)
	if base == "" {
		base = shortHash(account.InstanceID)
	}
	if count > 1 || account.SiteType == siteAWS {
		suffix := SlugDDNS(account.InstanceName)
		if suffix == "" {
			suffix = SlugDDNS(strings.TrimPrefix(account.InstanceID, "i-"))
		}
		if suffix != "" && suffix != base {
			base += "-" + suffix
		}
	}
	return base
}

func NormalizeDDNSDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	if index := strings.IndexByte(value, '/'); index >= 0 {
		value = value[:index]
	}
	return strings.Trim(value, ".")
}

func SlugDDNS(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = ddnsSlugPattern.ReplaceAllString(value, "-")
	return strings.Trim(strings.TrimSpace(value), "-")
}

func shortHash(value string) string {
	hash := sha1.Sum([]byte(value))
	return hex.EncodeToString(hash[:])[:8]
}

// InstanceDNSName is the full name the instance's own record uses under
// domain: the user's chosen name if any, otherwise the automatic one.
func (s *Store) InstanceDNSName(account app.Account, accounts []app.Account, domain string) string {
	return s.DDNSNameForDomain(account, accounts, s.CustomDNSName(account), domain)
}

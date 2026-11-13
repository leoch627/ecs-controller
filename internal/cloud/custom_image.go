package cloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CustomImageSpec describes a disk image file that should become an ECS custom
// image. SourceURL is downloaded by the controller, staged in OSS, and imported.
type CustomImageSpec struct {
	Name       string
	SourceURL  string
	DiskSizeGB int
}

// CustomImageClient is optional so lightweight fake cloud clients keep working.
type CustomImageClient interface {
	// FindCustomImage returns the newest self-owned image with exactly this
	// name, in any state. An empty id means there is none.
	FindCustomImage(ctx context.Context, region, name string) (id, status string, err error)
	// EnsureCustomImage returns an Available custom image id, importing the
	// image through OSS when the account does not have it yet.
	EnsureCustomImage(ctx context.Context, region string, spec CustomImageSpec, progress func(string)) (string, error)
	// DeleteImportedImage removes an image this controller imported, together
	// with its snapshot, so nothing keeps accruing storage fees. Images the
	// user created some other way are left alone and reported as not deleted.
	DeleteImportedImage(ctx context.Context, region, id string) (deleted bool, err error)
}

const (
	imageImportRole      = "AliyunECSImageImportDefaultRole"
	imageImportPolicy    = "AliyunECSImageImportRolePolicy"
	importedImageMark    = "imported by ecs-controller"
	maxImageDownloadSize = 8 << 30
	imageAllStatuses     = "Creating,Waiting,Available,UnAvailable,CreateFailed"
)

// CustomImageName turns a user supplied name (or, when empty, the file name in
// the download URL) into a valid ECS image name.
func CustomImageName(name, sourceURL string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		if parsed, err := url.Parse(sourceURL); err == nil {
			name = path.Base(parsed.Path)
		}
		for _, ext := range []string{".qcow2", ".raw", ".img", ".vhd", ".vmdk"} {
			name = strings.TrimSuffix(name, ext)
		}
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r >= 0x4e00 && r <= 0x9fff:
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name = strings.Trim(b.String(), "-._")
	if name == "" {
		name = "image"
	}
	if first := name[0]; first < 0x80 && !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		name = "img-" + name
	}
	if len(name) < 2 {
		name = "img-" + name
	}
	if len(name) > 100 {
		name = name[:100]
	}
	return name
}

func (s *Service) FindCustomImage(ctx context.Context, region, name string) (string, string, error) {
	result, err := s.ECS.Call(ctx, "DescribeImages", map[string]string{"RegionId": region, "ImageOwnerAlias": "self", "ImageName": name, "Status": imageAllStatuses, "PageSize": "100"})
	if err != nil {
		return "", "", err
	}
	var id, status, created string
	for _, image := range mapsAt(result, "Images.Image") {
		// ImageName is a fuzzy filter, so require the exact name here.
		if stringValue(image["ImageName"]) != name {
			continue
		}
		candidate := stringValue(image["Status"])
		// Prefer a usable image, then the most recent one.
		if id == "" || (candidate == "Available" && status != "Available") || (candidate == status && stringValue(image["CreationTime"]) > created) {
			id, status, created = stringValue(image["ImageId"]), candidate, stringValue(image["CreationTime"])
		}
	}
	return id, status, nil
}

func (s *Service) EnsureCustomImage(ctx context.Context, region string, spec CustomImageSpec, progress func(string)) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if spec.Name == "" {
		return "", fmt.Errorf("自定义镜像名称为空")
	}
	id, status, err := s.FindCustomImage(ctx, region, spec.Name)
	if err != nil {
		return "", fmt.Errorf("查询自定义镜像失败: %w", err)
	}
	switch status {
	case "Available":
		return id, nil
	case "Creating", "Waiting":
		// An earlier attempt already started the import; just keep waiting.
		return id, s.waitImageAvailable(ctx, region, id, progress)
	case "CreateFailed", "UnAvailable":
		_ = s.deleteImage(ctx, region, id)
	}
	if spec.SourceURL == "" {
		return "", fmt.Errorf("当前区域没有名为 %s 的自定义镜像，请填写镜像下载地址", spec.Name)
	}

	file, size, format, err := s.downloadImage(ctx, spec.SourceURL, progress)
	if err != nil {
		return "", err
	}
	defer file.Close()

	oss := s.imageOSS(region)
	bucket := imageBucketName(oss.AccessKey, region)
	object := spec.Name + "." + strings.ToLower(format)
	progress("创建 OSS Bucket " + bucket)
	if err := oss.PutBucket(ctx, bucket); err != nil {
		return "", fmt.Errorf("创建 OSS Bucket 失败: %w", err)
	}
	// The bucket only exists to hand the file to ECS; remove it afterwards so
	// it does not keep accruing storage fees.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = oss.DeleteObject(cleanupCtx, bucket, object)
		_ = oss.DeleteBucket(cleanupCtx, bucket)
	}()
	progress(fmt.Sprintf("上传镜像到 OSS（%d MB）", size>>20))
	if err := oss.PutObject(ctx, bucket, object, file, size); err != nil {
		return "", fmt.Errorf("上传镜像到 OSS 失败: %w", err)
	}

	progress("导入自定义镜像")
	s.ensureImageImportRole(ctx)
	diskSize := spec.DiskSizeGB
	if diskSize < 1 {
		diskSize = 1
	}
	params := map[string]string{
		"RegionId": region, "ImageName": spec.Name, "Description": importedImageMark,
		"Architecture": "x86_64", "OSType": "linux", "Platform": imagePlatform(spec.Name + " " + spec.SourceURL),
		"DiskDeviceMapping.1.OSSBucket": bucket, "DiskDeviceMapping.1.OSSObject": object,
		"DiskDeviceMapping.1.Format": format, "DiskDeviceMapping.1.DiskImageSize": strconv.Itoa(diskSize),
	}
	var result map[string]any
	for attempt := 0; ; attempt++ {
		result, err = s.ECS.Call(ctx, "ImportImage", params)
		// A role created a moment ago can take a few seconds to become visible.
		if err == nil || !isImportRoleError(err) || attempt >= 5 {
			break
		}
		if sleepCtx(ctx, 5*time.Second) != nil {
			break
		}
	}
	if err != nil {
		if isImportRoleError(err) {
			return "", fmt.Errorf("导入镜像失败：账号未授权 ECS 读取 OSS。请在 RAM 控制台创建角色 %s（受信服务 ecs.aliyuncs.com）并授予 %s，或给当前 AccessKey 增加 RAM 权限后重试: %w", imageImportRole, imageImportPolicy, err)
		}
		return "", fmt.Errorf("导入镜像失败: %w", err)
	}
	id = stringValue(result["ImageId"])
	if id == "" {
		return "", fmt.Errorf("ImportImage 未返回镜像 ID")
	}
	if err := s.waitImageAvailable(ctx, region, id, progress); err != nil {
		return "", err
	}
	_ = os.Remove(file.Name())
	return id, nil
}

func (s *Service) waitImageAvailable(ctx context.Context, region, id string, progress func(string)) error {
	deadline := time.Now().Add(40 * time.Minute)
	interval := s.ImagePollInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	for {
		result, err := s.ECS.Call(ctx, "DescribeImages", map[string]string{"RegionId": region, "ImageOwnerAlias": "self", "ImageId": id, "Status": imageAllStatuses})
		if err != nil {
			return fmt.Errorf("查询镜像导入进度失败: %w", err)
		}
		images := mapsAt(result, "Images.Image")
		if len(images) > 0 {
			switch stringValue(images[0]["Status"]) {
			case "Available":
				return nil
			case "CreateFailed", "UnAvailable":
				_ = s.deleteImage(ctx, region, id)
				return fmt.Errorf("镜像导入失败（%s），请确认镜像文件格式正确且系统盘大小不小于镜像虚拟磁盘大小", id)
			}
			if percent := stringValue(images[0]["Progress"]); percent != "" {
				progress("等待镜像导入完成 " + percent)
			} else {
				progress("等待镜像导入完成")
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("镜像 %s 导入超时，稍后重试创建会继续使用该镜像", id)
		}
		if err := sleepCtx(ctx, interval); err != nil {
			return err
		}
	}
}

func (s *Service) DeleteImportedImage(ctx context.Context, region, id string) (bool, error) {
	result, err := s.ECS.Call(ctx, "DescribeImages", map[string]string{"RegionId": region, "ImageOwnerAlias": "self", "ImageId": id, "Status": imageAllStatuses})
	if err != nil {
		return false, err
	}
	images := mapsAt(result, "Images.Image")
	if len(images) == 0 || stringValue(images[0]["Description"]) != importedImageMark {
		return false, nil
	}
	snapshots := make([]string, 0, 1)
	for _, mapping := range mapsAt(images[0], "DiskDeviceMappings.DiskDeviceMapping") {
		if snapshot := stringValue(mapping["SnapshotId"]); snapshot != "" {
			snapshots = append(snapshots, snapshot)
		}
	}
	// The snapshot cannot be removed while the image still references it.
	if err := s.deleteImage(ctx, region, id); err != nil {
		return false, err
	}
	for _, snapshot := range snapshots {
		if _, err := s.ECS.Call(ctx, "DeleteSnapshot", map[string]string{"SnapshotId": snapshot, "Force": "true"}); err != nil && !IsNotFound(err) {
			return true, fmt.Errorf("镜像已删除，但快照 %s 删除失败: %w", snapshot, err)
		}
	}
	return true, nil
}

func (s *Service) deleteImage(ctx context.Context, region, id string) error {
	_, err := s.ECS.Call(ctx, "DeleteImage", map[string]string{"RegionId": region, "ImageId": id, "Force": "true"})
	return err
}

// ensureImageImportRole creates the service role ECS assumes to read the OSS
// object. It is best effort: AccessKeys without RAM permission fall through
// to ImportImage, whose error then tells the user what to authorize.
func (s *Service) ensureImageImportRole(ctx context.Context) {
	if s.RAM == nil {
		return
	}
	if _, err := s.RAM.Call(ctx, "GetRole", map[string]string{"RoleName": imageImportRole}); err == nil {
		return
	}
	trust := `{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":["ecs.aliyuncs.com"]}}],"Version":"1"}`
	_, _ = s.RAM.Call(ctx, "CreateRole", map[string]string{"RoleName": imageImportRole, "AssumeRolePolicyDocument": trust, "Description": "Allows ECS to read image files from OSS when importing custom images"})
	_, _ = s.RAM.Call(ctx, "AttachPolicyToRole", map[string]string{"PolicyType": "System", "PolicyName": imageImportPolicy, "RoleName": imageImportRole})
}

func isImportRoleError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	code := strings.ToLower(apiErr.Code)
	return strings.Contains(code, "nosetroletoecsservice") || strings.Contains(code, "importrole")
}

func (s *Service) imageOSS(region string) *OSSClient {
	if s.ImageOSS != nil {
		return s.ImageOSS
	}
	// Uploads are large, so only bound the connection phases, not the body.
	return &OSSClient{HTTPClient: &http.Client{}, AccessKey: s.ECS.AccessKey, Secret: s.ECS.Secret, Region: region}
}

// imageBucketName is deterministic per AccessKey and region so a retried task
// reuses its own bucket instead of leaving a new one behind on every attempt.
func imageBucketName(accessKey, region string) string {
	sum := sha256.Sum256([]byte(accessKey + "/" + region))
	return "ecsctl-img-" + hex.EncodeToString(sum[:])[:20]
}

func imagePlatform(hint string) string {
	hint = strings.ToLower(hint)
	for key, platform := range map[string]string{"debian": "Debian", "ubuntu": "Ubuntu", "centos": "CentOS", "rocky": "Rocky Linux", "alma": "AlmaLinux", "fedora": "Fedora"} {
		if strings.Contains(hint, key) {
			return platform
		}
	}
	return "Others Linux"
}

// downloadImage fetches the image into a temp file keyed by its URL, so a
// retried task does not download it again, and detects the disk format.
func (s *Service) downloadImage(ctx context.Context, sourceURL string, progress func(string)) (*os.File, int64, string, error) {
	parsed, err := url.Parse(sourceURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, 0, "", fmt.Errorf("镜像下载地址无效，需要 http(s) 直链")
	}
	sum := sha256.Sum256([]byte(sourceURL))
	target := filepath.Join(os.TempDir(), "ecsctl-image-"+hex.EncodeToString(sum[:])[:16])
	if _, statErr := os.Stat(target); statErr != nil {
		progress("下载镜像文件")
		if err := s.fetchToFile(ctx, sourceURL, target, progress); err != nil {
			return nil, 0, "", err
		}
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, 0, "", err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, "", err
	}
	format, err := detectImageFormat(file, info.Size())
	if err != nil {
		file.Close()
		_ = os.Remove(target)
		return nil, 0, "", err
	}
	return file, info.Size(), format, nil
}

func (s *Service) fetchToFile(ctx context.Context, sourceURL, target string, progress func(string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return err
	}
	client := s.ImageHTTP
	if client == nil {
		client = &http.Client{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载镜像失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载镜像失败: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxImageDownloadSize {
		return fmt.Errorf("镜像文件超过 %d GB 上限", maxImageDownloadSize>>30)
	}
	partial, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".part-*")
	if err != nil {
		return err
	}
	defer os.Remove(partial.Name())
	defer partial.Close()
	reader := &progressReader{reader: io.LimitReader(resp.Body, maxImageDownloadSize+1), total: resp.ContentLength, report: progress}
	written, err := io.Copy(partial, reader)
	if err != nil {
		return fmt.Errorf("下载镜像失败: %w", err)
	}
	if written > maxImageDownloadSize {
		return fmt.Errorf("镜像文件超过 %d GB 上限", maxImageDownloadSize>>30)
	}
	if written == 0 {
		return fmt.Errorf("下载到的镜像文件为空")
	}
	if err := partial.Close(); err != nil {
		return err
	}
	return os.Rename(partial.Name(), target)
}

type progressReader struct {
	reader   io.Reader
	total    int64
	read     int64
	reported time.Time
	report   func(string)
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.reader.Read(buf)
	p.read += int64(n)
	if time.Since(p.reported) > 3*time.Second {
		p.reported = time.Now()
		if p.total > 0 {
			p.report(fmt.Sprintf("下载镜像文件 %d / %d MB", p.read>>20, p.total>>20))
		} else {
			p.report(fmt.Sprintf("下载镜像文件 %d MB", p.read>>20))
		}
	}
	return n, err
}

// detectImageFormat sniffs the disk format ImportImage needs and rejects
// compressed archives, which ECS cannot import. It leaves the file at offset 0.
func detectImageFormat(file *os.File, size int64) (string, error) {
	head := make([]byte, 8)
	if _, err := io.ReadFull(file, head); err != nil {
		return "", fmt.Errorf("镜像文件过小或无法读取")
	}
	tail := make([]byte, 8)
	if size >= 512 {
		_, _ = file.ReadAt(tail, size-512)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	switch {
	case string(head[:4]) == "QFI\xfb":
		return "QCOW2", nil
	case string(head[:4]) == "KDMV":
		return "VMDK", nil
	case string(head) == "conectix" || string(tail) == "conectix":
		return "VHD", nil
	case string(head[:6]) == "\xfd7zXZ\x00", head[0] == 0x1f && head[1] == 0x8b, string(head[:4]) == "\x28\xb5\x2f\xfd", string(head[:2]) == "PK", string(head[:3]) == "BZh":
		return "", fmt.Errorf("镜像文件是压缩包，请提供解压后的 qcow2 / raw / vhd 直链")
	case string(head[:5]) == "<!DOC" || string(head[:5]) == "<html" || string(head[:5]) == "<!doc":
		return "", fmt.Errorf("下载地址返回的是网页而不是镜像文件，请使用文件直链")
	}
	return "RAW", nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

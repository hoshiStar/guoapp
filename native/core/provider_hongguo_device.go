package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const hongguoDeviceRegisterURL = "https://log.snssdk.com/service/2/device_register/"

const hongguoDeviceRotations = 3

const hongguoDeviceRegisterPause = 10 * time.Minute

var hongguoRegisterDeviceID = regexp.MustCompile(`^[0-9]{1,32}$`)

type hongguoRegisterRejection struct{ err error }

func (rejection hongguoRegisterRejection) Error() string { return rejection.err.Error() }

func (rejection hongguoRegisterRejection) Unwrap() error { return rejection.err }

type hongguoDeviceRegistrar struct {
	mu          sync.Mutex
	pausedUntil time.Time
}

func (registrar *hongguoDeviceRegistrar) ensure(ctx context.Context, downloader *Downloader, rejected string) error {
	registrar.mu.Lock()
	defer registrar.mu.Unlock()
	client := downloader.hongguoClient()
	client.mu.Lock()
	deviceID, installID, registered := client.state.DeviceID, client.state.InstallID, client.state.Registered
	client.mu.Unlock()
	settled := rejected == "" && registered && hongguoRegisterDeviceID.MatchString(deviceID)
	settled = settled || rejected != "" && rejected != deviceID
	if settled {
		return nil
	}
	if time.Now().Before(registrar.pausedUntil) {
		return errors.New("红果设备注册刚被拒绝，稍后再试")
	}
	deviceID, installID, err := downloader.registerHongguoDevice(ctx)
	if err != nil {
		var rejection hongguoRegisterRejection
		if errors.As(err, &rejection) {
			registrar.pausedUntil = time.Now().Add(hongguoDeviceRegisterPause)
		}
		return err
	}
	registrar.pausedUntil = time.Time{}
	client.mu.Lock()
	client.state.DeviceID = deviceID
	client.state.InstallID = installID
	client.state.Registered = true
	client.mu.Unlock()
	return nil
}

func (downloader *Downloader) registerHongguoDevice(ctx context.Context) (string, string, error) {
	query := hongguoDeviceRegisterQuery()
	header := map[string]any{
		"display_name": "红果免费短剧", "aid": 8662, "app_version": "7.3.5.32", "version_code": 73532,
		"manifest_version_code": 73532, "update_version_code": 73532, "channel": "update_64",
		"package": "com.phoenix.read", "app_language": "zh", "os": "Android", "os_version": "16", "os_api": 36,
		"device_model": "25053RT47C", "device_brand": "Redmi", "device_manufacturer": "Xiaomi",
		"cpu_abi": "arm64-v8a", "density_dpi": 520, "display_density": "xxhdpi", "resolution": "2772x1280",
		"language": "zh", "timezone": 8, "access": "wifi", "openudid": randomHex(8),
		"clientudid": uuidLike(), "cdid": uuidLike(), "region": "CN", "tz_name": "Asia/Shanghai",
		"tz_offset": 28800, "sim_region": "cn", "device_platform": "android", "not_request_sender": 0,
		"is_system_app": 0, "sdk_flavor": "china", "rom": "OS2.0", "rom_version": "BP2A.250605.031.A3",
	}
	body, err := json.Marshal(map[string]any{"magic_tag": "ss_app_log", "header": header, "_gen_time": time.Now().UnixMilli()})
	if err != nil {
		return "", "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, hongguoDeviceRegisterURL+"?"+query.Encode(), bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	request.Header.Set("User-Agent", hongguoAppUserAgent)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := downloader.doPreparedCatalogRequest(request, 20*time.Second, nil)
	if err != nil {
		return "", "", err
	}
	content, readErr := io.ReadAll(io.LimitReader(response.Body, providerMaxBodyBytes))
	response.Body.Close()
	if readErr != nil {
		return "", "", readErr
	}
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("红果设备注册 HTTP %d", response.StatusCode)
	}
	var registered map[string]any
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&registered); err != nil {
		return "", "", hongguoRegisterRejection{fmt.Errorf("红果设备注册返回格式异常")}
	}
	deviceID := firstNonEmpty(mapString(registered, "device_id_str"), mapString(registered, "device_id"))
	installID := firstNonEmpty(mapString(registered, "install_id_str"), mapString(registered, "install_id"))
	if !hongguoRegisterDeviceID.MatchString(deviceID) || deviceID == "0" || !hongguoRegisterDeviceID.MatchString(installID) || installID == "0" {
		return "", "", hongguoRegisterRejection{fmt.Errorf("红果设备注册未返回有效设备标识")}
	}
	return deviceID, installID, nil
}

func hongguoDeviceRegisterQuery() url.Values {
	return url.Values{
		"aid": {"8662"}, "app_name": {"novelread"}, "version_code": {"73532"}, "version_name": {"7.3.5.32"},
		"manifest_version_code": {"73532"}, "update_version_code": {"73532"}, "channel": {"update_64"},
		"device_platform": {"android"}, "os": {"android"}, "ssmix": {"a"}, "device_type": {"25053RT47C"},
		"device_brand": {"Redmi"}, "language": {"zh"}, "os_api": {"36"}, "os_version": {"16"},
		"resolution": {"1280*2772"}, "dpi": {"520"}, "ac": {"wifi"},
		"req_id": {uuidLike()}, "_rticket": {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	}
}

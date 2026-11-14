package core

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// 假服务端：完整复刻 dx150-edge-v1 的握手与信封，用来验证客户端真的按协议走。
type edgeFakeSession struct {
	scope  string
	info   string
	reqKey []byte
	resKey []byte
	seqs   []uint32
}

type edgeFake struct {
	t        *testing.T
	mu       sync.Mutex
	sessions map[string]*edgeFakeSession
	detail   string
	playback string
	cdnHeads []http.Header
	m3u8     string
}

func newEdgeFake(t *testing.T) *edgeFake {
	return &edgeFake{t: t, sessions: map[string]*edgeFakeSession{},
		m3u8: "#EXTM3U\n#EXT-X-TARGETDURATION:10\n#EXTINF:10.0,\nseg1.ts\n#EXT-X-ENDLIST\n"}
}

func (f *edgeFake) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Host == "yd-lphu-hls.hzjvlo.cn" {
		f.mu.Lock()
		f.cdnHeads = append(f.cdnHeads, request.Header.Clone())
		f.mu.Unlock()
		return sourceFixtureResponse(request, http.StatusOK, f.m3u8), nil
	}
	blob, _ := io.ReadAll(request.Body)
	var envelope map[string]any
	if err := json.Unmarshal(blob, &envelope); err != nil {
		f.t.Fatalf("通道请求不是 JSON: %v", err)
	}
	scope := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/api/"), "/request")
	switch envelope["type"] {
	case "hello":
		return f.hello(request, scope, envelope)
	case "call":
		return f.call(request, scope, envelope)
	}
	f.t.Fatalf("未知信封类型 %v", envelope["type"])
	return nil, nil
}

func (f *edgeFake) hello(request *http.Request, scope string, envelope map[string]any) (*http.Response, error) {
	clientRaw, err := base64.RawURLEncoding.DecodeString(envelope["client_pub"].(string))
	if err != nil {
		f.t.Fatalf("client_pub 不是 base64url: %v", err)
	}
	clientPub, err := ecdh.P256().NewPublicKey(clientRaw)
	if err != nil {
		f.t.Fatalf("client_pub 不是 P-256 点: %v", err)
	}
	serverKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	shared, err := serverKey.ECDH(clientPub)
	if err != nil {
		f.t.Fatal(err)
	}
	salt := make([]byte, 32)
	rand.Read(salt)
	sid := "sid-" + scope
	info := strings.Join([]string{huangguoEdgeProtocol, scope, "huangguoai.com", "v20261109", sid}, "\n")
	session := &edgeFakeSession{scope: scope, info: info}
	session.reqKey, err = hkdf.Key(sha256.New, shared, salt, info+"\nreq", 32)
	if err != nil {
		f.t.Fatal(err)
	}
	session.resKey, err = hkdf.Key(sha256.New, shared, salt, info+"\nres", 32)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.sessions[sid] = session
	f.mu.Unlock()
	reply, _ := json.Marshal(map[string]any{
		"v": 1, "type": "hello", "kid": "v20261109", "sid": sid,
		"server_pub": base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		"salt":       base64.RawURLEncoding.EncodeToString(salt),
		"site":       "huangguoai.com", "server_time": 1794679500, "expires_at": 1794680100,
	})
	return sourceFixtureResponse(request, http.StatusOK, string(reply)), nil
}

func (f *edgeFake) call(request *http.Request, scope string, envelope map[string]any) (*http.Response, error) {
	sid := envelope["sid"].(string)
	f.mu.Lock()
	session := f.sessions[sid]
	f.mu.Unlock()
	if session == nil {
		f.t.Fatalf("未知 sid %s", sid)
	}
	seq := uint32(envelope["seq"].(float64))
	f.mu.Lock()
	session.seqs = append(session.seqs, seq)
	f.mu.Unlock()
	iv := make([]byte, 12)
	binary.BigEndian.PutUint32(iv[8:], seq)
	ts := envelope["ts"].(float64)
	aad := session.info + "\nreq\n" + strconv.Itoa(int(seq)) + "\n" + strconv.Itoa(int(ts))
	sealed, err := base64.RawURLEncoding.DecodeString(envelope["ciphertext"].(string))
	if err != nil {
		f.t.Fatalf("ciphertext 不是 base64url: %v", err)
	}
	plain, err := huangguoEdgeOpen(session.reqKey, iv, sealed, aad)
	if err != nil {
		f.t.Fatalf("请求信封解不开（AAD/iv/密钥不对）: %v", err)
	}
	var packet struct {
		Request struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Body   string `json:"body"`
		} `json:"request"`
	}
	if err := json.Unmarshal(plain, &packet); err != nil {
		f.t.Fatalf("请求明文不是 JSON: %v", err)
	}
	payload := f.payload(scope, packet.Request.Method, packet.Request.Path)
	inner, _ := json.Marshal(map[string]any{
		"status": http.StatusOK, "headers": map[string]any{"content-type": "application/json"},
		"body": base64.StdEncoding.EncodeToString([]byte(payload)),
	})
	aadRes := session.info + "\nres\n" + strconv.Itoa(int(seq)) + "\n" + strconv.Itoa(int(ts))
	sealedReply, err := huangguoEdgeSeal(session.resKey, iv, inner, aadRes)
	if err != nil {
		f.t.Fatal(err)
	}
	reply, _ := json.Marshal(map[string]any{
		"v": 1, "type": "result", "kid": "v20261109", "sid": sid, "seq": seq,
		"ts": ts, "ciphertext": base64.RawURLEncoding.EncodeToString(sealedReply),
	})
	return sourceFixtureResponse(request, http.StatusOK, string(reply)), nil
}

func (f *edgeFake) payload(scope, method, path string) string {
	switch {
	case scope == huangguoEdgeScopeInfo && method == http.MethodGet && path == "/api/videos/10374":
		return f.detail
	case scope == huangguoEdgeScopePlay && method == http.MethodPost:
		return f.playback
	}
	f.t.Fatalf("假服务端未覆盖 %s %s (%s)", method, path, scope)
	return ""
}

func edgeFakeDownloader(t *testing.T, fake *edgeFake) *Downloader {
	t.Helper()
	fake.t = t
	return sourceFixtureDownloader(t, fake.RoundTrip)
}

const edgeDetailJSON = `{"status":1,"data":{"id":10374,"title":"锁情咒","description":"简介",
"cover":"https://pic.drleao.cn/a.jpeg","episode_count":2,
"episodes":[{"ep_num":1,"title":"第1集","duration":744},{"ep_num":2,"title":"第2集","duration":890}],
"tags":["复仇",{"name":"复仇"}]}}`

const edgePlaybackJSON = `{"status":1,"data":{"id":"10374","ep":2,
"streams":{"main":"https://yd-lphu-hls.hzjvlo.cn/videos5/aa/bb.m3u8?auth_key=1","hevc":""},
"cdn":{"m3u8Enabled":true,"authKey":"x-cdn-auth","authValue":"deadbeef","app":"150"}}}`

func TestHuangguoEdgeDetailAndPlayback(t *testing.T) {
	fake := newEdgeFake(t)
	fake.detail = edgeDetailJSON
	fake.playback = edgePlaybackJSON
	downloader := edgeFakeDownloader(t, fake)
	ctx := context.Background()

	drama, chapters, err := downloader.fetchHuangguoEdgeDetail(ctx, "video/10374")
	if err != nil {
		t.Fatalf("详情失败: %v", err)
	}
	if drama.Title != "锁情咒" || drama.SourceID != "10374" || drama.Source != sourceHuangguoAI {
		t.Fatalf("详情字段不对: %+v", drama)
	}
	if drama.EpisodeCount != 2 || len(chapters) != 2 {
		t.Fatalf("集数不对: count=%d chapters=%d", drama.EpisodeCount, len(chapters))
	}
	if chapters[1].Title != "第2集" || chapters[1].PageURL != "https://huangguoai.com/video/10374/" {
		t.Fatalf("章节字段不对: %+v", chapters[1])
	}
	if len(drama.Tags) != 1 || drama.Tags[0] != "复仇" {
		t.Fatalf("标签处理不对: %+v", drama.Tags)
	}

	task := Task{DramaID: drama.ID, Chapter: chapters[1], Index: 1}
	media, err := downloader.resolveHuangguoEdgeMedia(ctx, task)
	if err != nil {
		t.Fatalf("取流失败: %v", err)
	}
	if !strings.HasPrefix(media.Playlist, "#EXTM3U") {
		t.Fatalf("没有拿到播放列表: %q", media.Playlist)
	}
	if media.Duration <= 0 {
		t.Fatalf("播放列表时长未解析: %v", media.Duration)
	}
	if len(fake.cdnHeads) != 1 {
		t.Fatalf("m3u8 请求次数不对: %d", len(fake.cdnHeads))
	}
	if got := fake.cdnHeads[0].Get("x-cdn-auth"); got != "deadbeef" {
		t.Fatalf("CDN 鉴权头没透传: %q", got)
	}
	if got := fake.cdnHeads[0].Get("x-cdn-app"); got != "150" {
		t.Fatalf("CDN app 头没透传: %q", got)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.sessions) != 2 {
		t.Fatalf("详情与播放各用一条会话，实际 %d 条", len(fake.sessions))
	}
	for sid, session := range fake.sessions {
		for index, seq := range session.seqs {
			if seq != uint32(index+1) {
				t.Fatalf("会话 %s 的 seq 未从 1 递增: %v", sid, session.seqs)
			}
		}
	}
}

func TestHuangguoEdgeSessionReuse(t *testing.T) {
	fake := newEdgeFake(t)
	fake.detail = edgeDetailJSON
	downloader := edgeFakeDownloader(t, fake)
	for round := 0; round < 3; round++ {
		if _, _, err := downloader.fetchHuangguoEdgeDetail(context.Background(), "10374"); err != nil {
			t.Fatalf("第 %d 轮详情失败: %v", round, err)
		}
	}
	if len(fake.sessions) != 1 {
		t.Fatalf("同一 scope 应复用一条会话，实际 %d 条", len(fake.sessions))
	}
}

func TestHuangguoEdgeVideoID(t *testing.T) {
	cases := map[string]string{
		"10374":           "10374",
		"video/10374":     "10374",
		"/video/10374/":   "10374",
		"detail/10374":    "10374",
		"10374/ep-2":      "10374",
		"10374:1":         "10374",
		"10374:1/ep-2":    "10374",
		"https://x/10374": "",
		"":                "",
		"abc":             "",
	}
	for input, want := range cases {
		if got := huangguoEdgeVideoID(input); got != want {
			t.Errorf("huangguoEdgeVideoID(%q) = %q, 期望 %q", input, got, want)
		}
	}
}

func TestHuangguoEdgeCDNHeaders(t *testing.T) {
	if headers := huangguoEdgeCDNHeaders(huangguoEdgeCDN{}); len(headers) != 0 {
		t.Fatalf("空 CDN 不应产生请求头: %+v", headers)
	}
	headers := huangguoEdgeCDNHeaders(huangguoEdgeCDN{AuthKey: "x-cdn-auth", AuthValue: "v", App: "150"})
	if headers["x-cdn-auth"] != "v" || headers["x-cdn-app"] != "150" {
		t.Fatalf("CDN 头不对: %+v", headers)
	}
}

package core

// 黄果 AI 站（huangguoai.com）自 2026-11 起把内容接口整体收进自研加密通道
// dx150-edge-v1：握手用 ECDH P-256 交换临时密钥，之后每个业务请求都是一条
// AES-256-GCM 信封（明文里包一层 HTTP 请求）。本文件只负责这套通道本身，
// 业务语义在 provider_huangguo_edge_api.go。

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	huangguoEdgeProtocol  = "dx150-edge-v1"
	huangguoEdgeScopeInfo = "dynamic"
	huangguoEdgeScopePlay = "playback"
	huangguoEdgeMaxSeq    = 16384
	huangguoEdgeSessionMS = 600 * 1000 // 服务端 hello 里 expires_at - server_time 恒为 600 秒
	huangguoEdgeUA        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)

type huangguoEdgeSession struct {
	scope     string
	kid       string
	sid       string
	info      string
	reqKey    []byte
	resKey    []byte
	offsetMS  int64
	expiresMS int64
	seq       uint32
}

type huangguoEdgeReply struct {
	Status  int
	Headers map[string]any
	Body    []byte
}

type huangguoEdgeClient struct {
	downloader *Downloader
	base       string
	mu         sync.Mutex
	sessions   map[string]*huangguoEdgeSession
}

func newHuangguoEdgeClient(d *Downloader) *huangguoEdgeClient {
	return &huangguoEdgeClient{
		downloader: d,
		base:       strings.TrimRight(d.providerBaseURL(sourceHuangguoAI), "/"),
		sessions:   make(map[string]*huangguoEdgeSession),
	}
}

// huangguoEdge 返回进程内共享的通道客户端；通道会话本身就是短期的，复用不会过期。
func (d *Downloader) huangguoEdge() *huangguoEdgeClient {
	d.huangguoEdgeOnce.Do(func() { d.huangguoEdgeClient = newHuangguoEdgeClient(d) })
	return d.huangguoEdgeClient
}

func (c *huangguoEdgeClient) postJSON(ctx context.Context, path string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", huangguoEdgeUA)
	request.Header.Set("Origin", c.base)
	request.Header.Set("Referer", c.base+"/")
	response, err := c.downloader.doCatalogRequestWithTimeout(request, providerTimeout)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	blob, err := io.ReadAll(io.LimitReader(response.Body, providerMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(blob) > providerMaxBodyBytes {
		return nil, fmt.Errorf("黄果 AI 加密通道响应过大")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("黄果 AI 加密通道 HTTP %d: %s", response.StatusCode, truncate(string(blob), 200))
	}
	return blob, nil
}

func (c *huangguoEdgeClient) open(ctx context.Context, scope string) (*huangguoEdgeSession, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	raw, err := c.postJSON(ctx, "/api/"+scope+"/request", map[string]any{
		"v": 1, "type": "hello",
		"client_pub": base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	})
	if err != nil {
		return nil, err
	}
	var hello struct {
		Type       string `json:"type"`
		Kid        string `json:"kid"`
		Sid        string `json:"sid"`
		ServerPub  string `json:"server_pub"`
		Salt       string `json:"salt"`
		Site       string `json:"site"`
		ServerTime int64  `json:"server_time"`
		ExpiresAt  int64  `json:"expires_at"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &hello); err != nil {
		return nil, fmt.Errorf("黄果 AI 加密通道握手响应无法解析: %w", err)
	}
	if hello.Error != "" {
		return nil, fmt.Errorf("黄果 AI 加密通道握手被拒: %s", hello.Error)
	}
	if hello.Type != "hello" || hello.Kid == "" || hello.Sid == "" || hello.ServerPub == "" || hello.Salt == "" {
		return nil, errors.New("黄果 AI 加密通道握手响应缺少必要字段")
	}
	serverRaw, err := base64.RawURLEncoding.DecodeString(hello.ServerPub)
	if err != nil {
		return nil, err
	}
	serverPub, err := ecdh.P256().NewPublicKey(serverRaw)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	salt, err := base64.RawURLEncoding.DecodeString(hello.Salt)
	if err != nil {
		return nil, err
	}
	info := strings.Join([]string{huangguoEdgeProtocol, scope, hello.Site, hello.Kid, hello.Sid}, "\n")
	reqKey, err := hkdf.Key(sha256.New, shared, salt, info+"\nreq", 32)
	if err != nil {
		return nil, err
	}
	resKey, err := hkdf.Key(sha256.New, shared, salt, info+"\nres", 32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	return &huangguoEdgeSession{
		scope: scope, kid: hello.Kid, sid: hello.Sid, info: info,
		reqKey: reqKey, resKey: resKey,
		offsetMS: hello.ServerTime*1000 - now, expiresMS: hello.ExpiresAt * 1000,
	}, nil
}

// session 返回可用会话；seq 用尽或临近过期时重开一条。
func (c *huangguoEdgeClient) session(ctx context.Context, scope string) (*huangguoEdgeSession, error) {
	if current := c.sessions[scope]; current != nil {
		if current.seq < huangguoEdgeMaxSeq && time.Now().UnixMilli() < current.expiresMS-5000 {
			return current, nil
		}
	}
	session, err := c.open(ctx, scope)
	if err != nil {
		delete(c.sessions, scope)
		return nil, err
	}
	c.sessions[scope] = session
	return session, nil
}

func (c *huangguoEdgeClient) call(ctx context.Context, scope, method, path string, body []byte, contentType string) (huangguoEdgeReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	session, err := c.session(ctx, scope)
	if err != nil {
		return huangguoEdgeReply{}, err
	}
	session.seq++
	seq := session.seq
	ts := time.Now().UnixMilli() + session.offsetMS
	tsSeconds := strconv.FormatInt(ts/1000, 10)
	plain, err := json.Marshal(map[string]any{"request": map[string]any{
		"method": method, "path": path,
		"body":         base64.StdEncoding.EncodeToString(body),
		"content_type": contentType,
	}})
	if err != nil {
		return huangguoEdgeReply{}, err
	}
	iv := make([]byte, 12)
	binary.BigEndian.PutUint32(iv[8:], seq)
	sealed, err := huangguoEdgeSeal(session.reqKey, iv, plain, session.info+"\nreq\n"+strconv.FormatUint(uint64(seq), 10)+"\n"+tsSeconds)
	if err != nil {
		return huangguoEdgeReply{}, err
	}
	raw, err := c.postJSON(ctx, "/api/"+scope+"/request", map[string]any{
		"v": 1, "type": "call", "kid": session.kid, "sid": session.sid,
		"seq": seq, "ts": ts / 1000, "ciphertext": base64.RawURLEncoding.EncodeToString(sealed),
	})
	if err != nil {
		return huangguoEdgeReply{}, err
	}
	var envelope struct {
		Type       string `json:"type"`
		Ciphertext string `json:"ciphertext"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return huangguoEdgeReply{}, fmt.Errorf("黄果 AI 加密通道响应无法解析: %w", err)
	}
	if envelope.Error != "" {
		delete(c.sessions, scope)
		return huangguoEdgeReply{}, fmt.Errorf("黄果 AI 加密通道拒绝请求: %s", envelope.Error)
	}
	sealedReply, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return huangguoEdgeReply{}, err
	}
	opened, err := huangguoEdgeOpen(session.resKey, iv, sealedReply, session.info+"\nres\n"+strconv.FormatUint(uint64(seq), 10)+"\n"+tsSeconds)
	if err != nil {
		return huangguoEdgeReply{}, err
	}
	var reply struct {
		Status  int            `json:"status"`
		Headers map[string]any `json:"headers"`
		Body    string         `json:"body"`
	}
	if err := json.Unmarshal(opened, &reply); err != nil {
		return huangguoEdgeReply{}, fmt.Errorf("黄果 AI 加密通道回包无法解析: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(reply.Body)
	if err != nil {
		return huangguoEdgeReply{}, err
	}
	return huangguoEdgeReply{Status: reply.Status, Headers: reply.Headers, Body: payload}, nil
}

func (c *huangguoEdgeClient) get(ctx context.Context, scope, path string) (huangguoEdgeReply, error) {
	return c.call(ctx, scope, http.MethodGet, path, nil, "")
}

func (c *huangguoEdgeClient) post(ctx context.Context, scope, path string, body []byte) (huangguoEdgeReply, error) {
	return c.call(ctx, scope, http.MethodPost, path, body, "application/json")
}

func huangguoEdgeSeal(key, iv, plain []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, iv, plain, []byte(aad)), nil
}

func huangguoEdgeOpen(key, iv, sealed []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, iv, sealed, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("黄果 AI 加密通道解密失败: %w", err)
	}
	return plain, nil
}

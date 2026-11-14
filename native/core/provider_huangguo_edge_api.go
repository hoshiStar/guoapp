package core

// 黄果 AI 站的业务接口。站点自 2026-11 起不再在 SSR 页面里吐播放地址，
// 全部走 provider_huangguo_edge.go 的加密通道：
//   GET  /api/videos/<id>            → 剧集详情（标题/集数/每集元数据）
//   POST /api/videos/<id>/playback   → 首集播放模型（含 m3u8）
//   POST /api/videos/<id>/episodes/<ep>/playback → 指定集播放模型
// 详情里的 episodes 只有 ep_num，没有播放地址；播放模型按需逐集取。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type huangguoEdgeStream struct {
	Main string `json:"main"`
	HEVC string `json:"hevc"`
}

type huangguoEdgeCDN struct {
	AuthKey   string `json:"authKey"`
	AuthValue string `json:"authValue"`
	App       string `json:"app"`
}

type huangguoEdgePlayback struct {
	ID      string             `json:"id"`
	Ep      int                `json:"ep"`
	Streams huangguoEdgeStream `json:"streams"`
	CDN     huangguoEdgeCDN    `json:"cdn"`
}

type huangguoEdgeEpisode struct {
	EpNum    int    `json:"ep_num"`
	Title    string `json:"title"`
	Duration int    `json:"duration"`
}

type huangguoEdgeDetail struct {
	ID           json.Number         `json:"id"`
	Title        string              `json:"title"`
	Description  string              `json:"description"`
	Cover        string              `json:"cover"`
	EpisodeCount int                 `json:"episode_count"`
	Episodes     []huangguoEdgeEpisode `json:"episodes"`
	Tags         []any               `json:"tags"`
}

// fetchHuangguoEdgeDetail 取剧集详情；sourceID 可以是纯数字 id，也允许带 /video/<id>/ 形态。
func (d *Downloader) fetchHuangguoEdgeDetail(ctx context.Context, sourceID string) (Drama, []Chapter, error) {
	id := huangguoEdgeVideoID(sourceID)
	if id == "" {
		return Drama{}, nil, fmt.Errorf("黄果 AI 剧集编号无效: %s", sourceID)
	}
	reply, err := d.huangguoEdge().get(ctx, huangguoEdgeScopeInfo, "/api/videos/"+url.PathEscape(id))
	if err != nil {
		return Drama{}, nil, err
	}
	if reply.Status != http.StatusOK {
		return Drama{}, nil, fmt.Errorf("黄果 AI 详情接口返回 HTTP %d", reply.Status)
	}
	var envelope struct {
		Data  huangguoEdgeDetail `json:"data"`
		Msg   string             `json:"msg"`
		Status json.Number       `json:"status"`
	}
	if err := json.Unmarshal(reply.Body, &envelope); err != nil {
		return Drama{}, nil, fmt.Errorf("黄果 AI 详情无法解析: %w", err)
	}
	detail := envelope.Data
	if strings.TrimSpace(detail.Title) == "" {
		return Drama{}, nil, fmt.Errorf("黄果 AI 未返回剧集 %s 的详情", id)
	}
	drama := Drama{
		ID: providerDramaID(sourceHuangguoAI, id), Source: sourceHuangguoAI, SourceID: id,
		Title: detail.Title, Name: detail.Title, Desc: detail.Description, Intro: detail.Description,
		Cover: detail.Cover, CoverURL: detail.Cover,
		TotalEpisode: detail.EpisodeCount, TotalEpisodeSnake: detail.EpisodeCount,
		EpisodeCount: detail.EpisodeCount, EpisodeCountSnake: detail.EpisodeCount,
		CategoryName: "AI成人短剧", CategoryNameSnake: "AI成人短剧",
		Tags: huangguoEdgeTagNames(detail.Tags),
	}
	chapters := huangguoEdgeChapters(id, detail)
	return drama, chapters, nil
}

func huangguoEdgeChapters(id string, detail huangguoEdgeDetail) []Chapter {
	pageURL := strings.TrimRight(huangguoAIBaseURL, "/") + "/video/" + url.PathEscape(id) + "/"
	episodes := detail.Episodes
	if len(episodes) == 0 && detail.EpisodeCount > 0 {
		for ep := 1; ep <= detail.EpisodeCount; ep++ {
			episodes = append(episodes, huangguoEdgeEpisode{EpNum: ep})
		}
	}
	sort.SliceStable(episodes, func(i, j int) bool { return episodes[i].EpNum < episodes[j].EpNum })
	chapters := make([]Chapter, 0, len(episodes))
	for position, episode := range episodes {
		number := episode.EpNum
		if number <= 0 {
			number = position + 1
		}
		title := strings.TrimSpace(episode.Title)
		if title == "" || strings.HasPrefix(title, "第") && strings.HasSuffix(title, "集") {
			title = fmt.Sprintf("第%d集", number)
		}
		chapters = append(chapters, Chapter{
			ID:             providerChapterID(sourceHuangguoAI, id, strconv.Itoa(number)),
			Source:         sourceHuangguoAI,
			Title:          title,
			CurrentEpisode: rawEpisode(number),
			PageURL:        pageURL,
		})
	}
	return chapters
}

// fetchHuangguoEdgePlayback 取某一集的播放模型。episode <= 0 表示首集。
func (d *Downloader) fetchHuangguoEdgePlayback(ctx context.Context, sourceID string, episode int) (huangguoEdgePlayback, error) {
	id := huangguoEdgeVideoID(sourceID)
	if id == "" {
		return huangguoEdgePlayback{}, fmt.Errorf("黄果 AI 剧集编号无效: %s", sourceID)
	}
	path := "/api/videos/" + url.PathEscape(id) + "/playback"
	if episode > 0 {
		path = "/api/videos/" + url.PathEscape(id) + "/episodes/" + strconv.Itoa(episode) + "/playback"
	}
	reply, err := d.huangguoEdge().post(ctx, huangguoEdgeScopePlay, path, []byte("{}"))
	if err != nil {
		return huangguoEdgePlayback{}, err
	}
	if reply.Status != http.StatusOK {
		return huangguoEdgePlayback{}, fmt.Errorf("黄果 AI 播放接口返回 HTTP %d", reply.Status)
	}
	var envelope struct {
		Data huangguoEdgePlayback `json:"data"`
		Msg  string               `json:"msg"`
	}
	if err := json.Unmarshal(reply.Body, &envelope); err != nil {
		return huangguoEdgePlayback{}, fmt.Errorf("黄果 AI 播放接口响应无法解析: %w", err)
	}
	playback := envelope.Data
	if strings.TrimSpace(playback.Streams.Main) == "" {
		return huangguoEdgePlayback{}, fmt.Errorf("黄果 AI 未返回第 %d 集的播放地址", episode)
	}
	return playback, nil
}

// resolveHuangguoEdgeMedia 把某一集解析成可直接播放的 providerMedia。
func (d *Downloader) resolveHuangguoEdgeMedia(ctx context.Context, task Task) (providerMedia, error) {
	_, sourceID, valid := splitProviderDramaID(task.DramaID)
	if !valid {
		sourceID = task.DramaID
	}
	episode := chapterEpisodeNumber(task.Chapter, task.Index)
	playback, err := d.fetchHuangguoEdgePlayback(ctx, sourceID, episode)
	if err != nil {
		return providerMedia{}, err
	}
	pageURL := firstNonEmpty(task.Chapter.PageURL, strings.TrimRight(huangguoAIBaseURL, "/")+"/video/"+url.PathEscape(huangguoEdgeVideoID(sourceID))+"/")
	return d.huangguoEdgeMediaFrom(ctx, playback.Streams.Main, playback.CDN, pageURL)
}

func (d *Downloader) huangguoEdgeMediaFrom(ctx context.Context, rawURL string, cdn huangguoEdgeCDN, referer string) (providerMedia, error) {
	media := providerMedia{URL: rawURL, Referer: referer}
	credentials := &providerMediaCredentials{referer: referer, headers: huangguoEdgeCDNHeaders(cdn)}
	if len(credentials.headers) > 0 {
		media.credentials = credentials
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.HasSuffix(strings.ToLower(parsed.Path), ".m3u8") {
		return media, nil
	}
	playlist, finalURL, err := d.fetchMediaPlaylist(providerMediaContext(ctx, credentials), rawURL, referer)
	if err != nil {
		return providerMedia{}, fmt.Errorf("获取播放列表失败: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(playlist, "\ufeff")), "#EXTM3U") {
		return providerMedia{}, fmt.Errorf("黄果 AI 未返回有效 M3U8")
	}
	if duration := m3u8Duration(playlist); duration > 0 {
		media.Duration = duration
	}
	media.Playlist = playlist
	media.URL = finalURL
	return media, nil
}

func huangguoEdgeCDNHeaders(cdn huangguoEdgeCDN) map[string]string {
	headers := map[string]string{}
	if strings.TrimSpace(cdn.AuthKey) != "" && strings.TrimSpace(cdn.AuthValue) != "" {
		headers[cdn.AuthKey] = cdn.AuthValue
	}
	if app := strings.TrimSpace(cdn.App); app != "" {
		headers["x-cdn-app"] = app
	}
	return headers
}

func huangguoEdgeVideoID(raw string) string {
	value := strings.Trim(strings.TrimSpace(raw), "/")
	for _, prefix := range []string{"video/", "detail/"} {
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimPrefix(value, prefix)
			value = strings.Trim(value, "/")
			break
		}
	}
	// 上游会把集号并进编号（章节 ID 的 sourceID 段形如 "10374:1"），
	// 剧集号只取第一个分隔符之前的部分。
	for _, separator := range []byte{'/', ':', '?'} {
		if index := strings.IndexByte(value, separator); index >= 0 {
			value = value[:index]
		}
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return value
}

func huangguoEdgeTagNames(tags []any) []string {
	var names []string
	seen := map[string]bool{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, tag := range tags {
		switch value := tag.(type) {
		case string:
			add(value)
		case map[string]any:
			add(mapString(value, "name", "title"))
		}
	}
	return names
}

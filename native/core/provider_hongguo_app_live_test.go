package core

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLiveHongguoAppMediaChain(t *testing.T) {
	if os.Getenv("CHECK_LIVE_PROVIDERS") != "true" {
		t.Skip("set CHECK_LIVE_PROVIDERS=true to touch the live hongguo app endpoints")
	}
	engine, err := newNativeEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.downloads.close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	downloader := engine.downloader

	dramas, err := downloader.fetchHongguoAppCatalogCategory(ctx, "")
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(dramas) == 0 {
		t.Fatal("catalog returned no dramas")
	}
	_, seriesID, ok := splitProviderDramaID(dramas[0].ID)
	if !ok {
		t.Fatalf("bad drama id %q", dramas[0].ID)
	}
	t.Logf("series=%s title=%s", seriesID, dramas[0].Title)

	entry, err := downloader.hongguoAppDetail(ctx, seriesID)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(entry.Chapters) == 0 {
		t.Fatal("detail returned no chapters")
	}
	t.Logf("chapters=%d first=%s", len(entry.Chapters), entry.Chapters[0].ID)

	videoID := trimHongguoCencPrefix(entry.Chapters[0].VideoURL)
	media, err := downloader.resolveHongguoAppMedia(ctx, videoID)
	if err != nil {
		t.Fatalf("resolveHongguoAppMedia: %v", err)
	}
	if media.URL == "" || len(media.CENCKey) == 0 {
		t.Fatalf("media incomplete: url=%q cenc=%d", media.URL, len(media.CENCKey))
	}
	t.Logf("quality=%d duration=%v variants=%d", media.Quality, media.Duration, len(media.Variants))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, media.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", hongguoAppUserAgent)
	response, err := downloader.doPreparedCatalogRequest(request, time.Minute, nil)
	if err != nil {
		t.Fatalf("media GET: %v", err)
	}
	head, _ := io.ReadAll(io.LimitReader(response.Body, 32))
	response.Body.Close()
	if response.StatusCode != http.StatusOK || len(head) == 0 {
		t.Fatalf("media GET status=%d len=%d", response.StatusCode, len(head))
	}
	t.Logf("media content-type=%q", response.Header.Get("Content-Type"))
}

func trimHongguoCencPrefix(value string) string {
	const prefix = "hongguo-cenc://"
	if len(value) > len(prefix) && value[:len(prefix)] == prefix {
		return value[len(prefix):]
	}
	return value
}

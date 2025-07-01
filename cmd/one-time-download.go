// Copyright (c) 2015-2024 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/minio/minio/internal/logger"
	"github.com/minio/mux"
	"github.com/minio/pkg/v3/policy"
)

// OneTimeToken 表示一次性下载令牌
type OneTimeToken struct {
	Token     string    `json:"token"`
	Bucket    string    `json:"bucket"`
	Object    string    `json:"object"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UsedCount int       `json:"used_count"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// OneTimeDownloadManager 管理一次性下载令牌
type OneTimeDownloadManager struct {
	tokens map[string]*OneTimeToken
	mu     sync.RWMutex
	stopCh chan struct{}
}

// TokenStats 令牌统计信息
type TokenStats struct {
	TotalTokens   int `json:"total_tokens"`
	ActiveTokens  int `json:"active_tokens"`
	ExpiredTokens int `json:"expired_tokens"`
	UsedTokens    int `json:"used_tokens"`
}

// OneTimeDownloadResponse 创建令牌的API响应
type OneTimeDownloadResponse struct {
	DownloadURL string        `json:"download_url"`
	Token       string        `json:"token"`
	ExpiresAt   time.Time     `json:"expires_at"`
	MaxUses     int           `json:"max_uses"`
	TokenInfo   *OneTimeToken `json:"token_info,omitempty"`
}

// globalOneTimeDownloadManager 全局一次性下载管理器
var globalOneTimeDownloadManager *OneTimeDownloadManager

// NewOneTimeDownloadManager 创建新的一次性下载管理器
func NewOneTimeDownloadManager() *OneTimeDownloadManager {
	manager := &OneTimeDownloadManager{
		tokens: make(map[string]*OneTimeToken),
		stopCh: make(chan struct{}),
	}

	// 启动清理goroutine
	go manager.cleanupExpiredTokens()

	return manager
}

// generateToken 生成随机令牌
func (m *OneTimeDownloadManager) generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// CreateOneTimeDownloadToken 创建一次性下载令牌
func (m *OneTimeDownloadManager) CreateOneTimeDownloadToken(bucket, object, createdBy string, expiresIn time.Duration, maxUses int) *OneTimeToken {
	m.mu.Lock()
	defer m.mu.Unlock()

	if maxUses <= 0 {
		maxUses = 1 // 默认只能使用一次
	}

	token := &OneTimeToken{
		Token:     m.generateToken(),
		Bucket:    bucket,
		Object:    object,
		ExpiresAt: time.Now().Add(expiresIn),
		MaxUses:   maxUses,
		UsedCount: 0,
		CreatedAt: time.Now(),
		CreatedBy: createdBy,
	}

	m.tokens[token.Token] = token
	logger.Info("创建一次性下载令牌: bucket=%s, object=%s, token=%s, expires=%s, max_uses=%d",
		bucket, object, token.Token, token.ExpiresAt.Format(time.RFC3339), maxUses)

	return token
}

// ValidateAndConsumeToken 验证并消费令牌
func (m *OneTimeDownloadManager) ValidateAndConsumeToken(tokenStr string) (*OneTimeToken, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[tokenStr]
	if !exists {
		logger.Info("令牌不存在: %s", tokenStr)
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(token.ExpiresAt) {
		logger.Info("令牌已过期: %s, expired_at=%s", tokenStr, token.ExpiresAt.Format(time.RFC3339))
		delete(m.tokens, tokenStr)
		return nil, false
	}

	// 检查使用次数
	if token.UsedCount >= token.MaxUses {
		logger.Info("令牌使用次数已达上限: %s, used=%d, max=%d", tokenStr, token.UsedCount, token.MaxUses)
		delete(m.tokens, tokenStr)
		return nil, false
	}

	// 增加使用次数
	token.UsedCount++
	logger.Info("消费一次性下载令牌: %s, used_count=%d/%d", tokenStr, token.UsedCount, token.MaxUses)

	// 如果使用次数达到上限，删除令牌
	if token.UsedCount >= token.MaxUses {
		delete(m.tokens, tokenStr)
		logger.Info("令牌使用完毕，已删除: %s", tokenStr)
	}

	return token, true
}

// RevokeToken 撤销令牌
func (m *OneTimeDownloadManager) RevokeToken(tokenStr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tokens[tokenStr]; exists {
		delete(m.tokens, tokenStr)
		logger.Info("撤销一次性下载令牌: %s", tokenStr)
		return true
	}
	return false
}

// GetTokenStats 获取令牌统计信息
func (m *OneTimeDownloadManager) GetTokenStats() TokenStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := TokenStats{
		TotalTokens: len(m.tokens),
	}

	now := time.Now()
	for _, token := range m.tokens {
		if now.After(token.ExpiresAt) {
			stats.ExpiredTokens++
		} else if token.UsedCount >= token.MaxUses {
			stats.UsedTokens++
		} else {
			stats.ActiveTokens++
		}
	}

	return stats
}

// cleanupExpiredTokens 定期清理过期令牌
func (m *OneTimeDownloadManager) cleanupExpiredTokens() {
	ticker := time.NewTicker(10 * time.Minute) // 每10分钟清理一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performCleanup()
		case <-m.stopCh:
			return
		}
	}
}

// performCleanup 执行清理操作
func (m *OneTimeDownloadManager) performCleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredCount := 0
	usedUpCount := 0

	for tokenStr, token := range m.tokens {
		shouldDelete := false

		if now.After(token.ExpiresAt) {
			expiredCount++
			shouldDelete = true
		} else if token.UsedCount >= token.MaxUses {
			usedUpCount++
			shouldDelete = true
		}

		if shouldDelete {
			delete(m.tokens, tokenStr)
		}
	}

	if expiredCount > 0 || usedUpCount > 0 {
		logger.Info("清理一次性下载令牌: expired=%d, used_up=%d, remaining=%d",
			expiredCount, usedUpCount, len(m.tokens))
	}
}

// Stop 停止管理器
func (m *OneTimeDownloadManager) Stop() {
	close(m.stopCh)
}

// CreateOneTimeDownloadHandler 创建一次性下载令牌的API处理器
func (api objectAPIHandlers) CreateOneTimeDownloadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "CreateOneTimeDownload")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// 检查权限
	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	// 验证对象是否存在
	opts := ObjectOptions{}
	_, err = objectAPI.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// 解析查询参数
	query := r.URL.Query()
	expiresInStr := query.Get("expires-in")
	maxUsesStr := query.Get("max-uses")

	expiresIn := 24 * time.Hour // 默认24小时
	if expiresInStr != "" {
		if seconds, err := strconv.Atoi(expiresInStr); err == nil && seconds > 0 {
			expiresIn = time.Duration(seconds) * time.Second
		}
	}

	maxUses := 1 // 默认只能使用一次
	if maxUsesStr != "" {
		if uses, err := strconv.Atoi(maxUsesStr); err == nil && uses > 0 {
			maxUses = uses
		}
	}

	// 限制最大过期时间和使用次数
	if expiresIn > 7*24*time.Hour {
		expiresIn = 7 * 24 * time.Hour // 最大7天
	}
	if maxUses > 100 {
		maxUses = 100 // 最大100次
	}

	// 获取创建者信息
	createdBy := "anonymous"
	if claims := mustGetClaimsFromToken(r); claims != nil {
		if accessKey, ok := claims["accessKey"].(string); ok && accessKey != "" {
			createdBy = accessKey
		}
	}

	// 创建令牌
	if globalOneTimeDownloadManager == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	token := globalOneTimeDownloadManager.CreateOneTimeDownloadToken(bucket, object, createdBy, expiresIn, maxUses)

	// 生成下载URL
	downloadURL := fmt.Sprintf("%s?one-time-token=%s",
		getObjectLocation(r, globalDomainNames, bucket, object),
		token.Token)

	response := OneTimeDownloadResponse{
		DownloadURL: downloadURL,
		Token:       token.Token,
		ExpiresAt:   token.ExpiresAt,
		MaxUses:     token.MaxUses,
		TokenInfo:   token,
	}

	// 返回响应
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.LogIf(ctx, "one-time-download", err)
	}
}

// OneTimeDownloadStatsHandler 获取令牌统计信息的管理API
func (a adminAPIHandlers) OneTimeDownloadStatsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "OneTimeDownloadStats")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := newObjectLayerFn()
	if objectAPI == nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if globalOneTimeDownloadManager == nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	stats := globalOneTimeDownloadManager.GetTokenStats()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		logger.LogIf(ctx, "one-time-download", err)
	}
}

// OneTimeDownloadRevokeHandler 撤销令牌的管理API
func (a adminAPIHandlers) OneTimeDownloadRevokeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "OneTimeDownloadRevoke")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := newObjectLayerFn()
	if objectAPI == nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if globalOneTimeDownloadManager == nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
		return
	}

	revoked := globalOneTimeDownloadManager.RevokeToken(token)

	response := map[string]interface{}{
		"revoked": revoked,
		"token":   token,
	}

	w.Header().Set("Content-Type", "application/json")
	if revoked {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.LogIf(ctx, "one-time-download", err)
	}
}

// 初始化一次性下载管理器
func init() {
	globalOneTimeDownloadManager = NewOneTimeDownloadManager()
}

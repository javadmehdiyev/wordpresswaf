package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	log     *logrus.Logger
	ipCache *cache.Cache
)

// SQL Injection regex patterns - Sadece gerçek saldırıları yakala
var sqlInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(union[\s\+]+select.+from|information_schema|sysdatabases|sysusers)`),
	regexp.MustCompile(`(?i)(drop[\s\+]+table|drop[\s\+]+database|truncate[\s\+]+table)`),
	regexp.MustCompile(`(?i)(exec[\s\+]+xp_|exec[\s\+]+sp_|waitfor[\s\+]+delay)`),
	regexp.MustCompile(`(?i)(';[\s\+]*?shutdown|';[\s\+]*?drop|--[\s\+]*?|\/\*!)`),
}

// XSS regex patterns - Sadece tehlikeli olanları yakala
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(<script.*?>[^<]*?(alert|eval|function|onclick).*?<\/script>)`),
	regexp.MustCompile(`(?i)(javascript:.*?(alert|eval|function|onclick))`),
	regexp.MustCompile(`(?i)(<img.*?onerror.*?=.*?(alert|eval|function).*?>)`),
}

// Path Traversal regex patterns - Sadece gerçek saldırıları yakala
var pathTraversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\.\./\.\./\.\./|\.\.\\\.\.\\\.\.\\)`),
	regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|c:\/windows\/system32)`),
}

// WordPress specific attack patterns - Normal WordPress yollarını engelleme
var wordpressPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(wp-config\.php$|eval-stdin\.php)`),
	regexp.MustCompile(`(?i)(wp-content/plugins/.*?/\.\./)`),
	regexp.MustCompile(`(?i)(wp-content/themes/.*?/\.\./)`),
}

// Shell command injection patterns - Sadece tehlikeli komutları yakala
var shellInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)([;&\|][\s]*?(ping -i|killall|wget|curl.*?eval|nc -e|netcat -e|bash -i))`),
	regexp.MustCompile(`(?i)(system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\()`),
}

type WAF struct {
	config    *viper.Viper
	rateLimit map[string]int
}

func init() {
	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})

	// Log dosyasını ayarla
	logFile, err := os.OpenFile("/var/log/waf/waf.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(fmt.Sprintf("Log dosyası açılamadı: %v", err))
	}
	log.SetOutput(logFile)

	ipCache = cache.New(5*time.Minute, 10*time.Minute)
}

func NewWAF() (*WAF, error) {
	config := viper.New()
	config.SetConfigName("config")
	config.SetConfigType("yaml")
	config.AddConfigPath(".")

	if err := config.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config okuma hatası: %v", err)
	}

	return &WAF{
		config:    config,
		rateLimit: make(map[string]int),
	}, nil
}

func (w *WAF) checkRequest(c *gin.Context) (bool, string, string) {
	// WordPress admin ve login sayfalarını kontrol etme
	if strings.Contains(c.Request.URL.Path, "/wp-admin") ||
		strings.Contains(c.Request.URL.Path, "/wp-login.php") {
		return false, "", ""
	}

	// Static dosyaları kontrol etme
	if strings.HasSuffix(c.Request.URL.Path, ".css") ||
		strings.HasSuffix(c.Request.URL.Path, ".js") ||
		strings.HasSuffix(c.Request.URL.Path, ".png") ||
		strings.HasSuffix(c.Request.URL.Path, ".jpg") ||
		strings.HasSuffix(c.Request.URL.Path, ".jpeg") ||
		strings.HasSuffix(c.Request.URL.Path, ".gif") ||
		strings.HasSuffix(c.Request.URL.Path, ".svg") ||
		strings.HasSuffix(c.Request.URL.Path, ".woff") ||
		strings.HasSuffix(c.Request.URL.Path, ".woff2") ||
		strings.HasSuffix(c.Request.URL.Path, ".ttf") {
		return false, "", ""
	}

	// Original URI'yi al
	originalURI := c.GetHeader("X-Original-URI")
	if originalURI == "" {
		originalURI = c.Request.URL.String()
	}

	// Request body'sini oku
	var bodyBytes []byte
	if c.Request.Body != nil && c.Request.Method == "POST" {
		bodyBytes, _ = ioutil.ReadAll(c.Request.Body)
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Payload'ı birleştir
	payload := fmt.Sprintf("%s %s %s",
		originalURI,
		string(bodyBytes),
		c.Request.Referer(),
	)

	// Payload'ı decode et
	decodedPayload := w.decodePayload(payload)

	// Saldırı kontrolleri
	if found, pattern := w.checkPayload(sqlInjectionPatterns, decodedPayload); found {
		return true, "SQL Injection", pattern
	}

	if found, pattern := w.checkPayload(xssPatterns, decodedPayload); found {
		return true, "XSS", pattern
	}

	if found, pattern := w.checkPayload(pathTraversalPatterns, decodedPayload); found {
		return true, "Path Traversal", pattern
	}

	if found, pattern := w.checkPayload(shellInjectionPatterns, decodedPayload); found {
		return true, "Shell Injection", pattern
	}

	return false, "", ""
}

func (w *WAF) checkPayload(patterns []*regexp.Regexp, payload string) (bool, string) {
	for _, pattern := range patterns {
		if match := pattern.FindString(payload); match != "" {
			return true, match
		}
	}
	return false, ""
}

func (w *WAF) decodePayload(payload string) string {
	// URL decode
	decoded, err := url.QueryUnescape(payload)
	if err == nil {
		payload = decoded
	}

	// Base64 decode attempt
	if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil {
		payload = string(decoded)
	}

	// Unicode decode
	payload = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, payload)

	return payload
}

func (w *WAF) checkRateLimit(c *gin.Context) bool {
	ip := c.ClientIP()
	maxRequests := w.config.GetInt("security.rate_limit.requests")
	perSeconds := w.config.GetInt("security.rate_limit.per_seconds")

	if count, found := ipCache.Get(ip); found {
		if count.(int) >= maxRequests {
			log.WithFields(logrus.Fields{
				"ip":    ip,
				"count": count,
			}).Warn("Rate limit aşıldı")
			return true
		}
		ipCache.Set(ip, count.(int)+1, time.Duration(perSeconds)*time.Second)
	} else {
		ipCache.Set(ip, 1, time.Duration(perSeconds)*time.Second)
	}
	return false
}

func (w *WAF) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		clientIP := c.ClientIP()

		// Blacklist kontrolü
		blockedIPs := w.config.GetStringSlice("security.blocked_ips")
		for _, ip := range blockedIPs {
			if ip == clientIP {
				log.WithFields(logrus.Fields{
					"ip": clientIP,
				}).Warn("Engelli IP erişim denemesi")
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		// Whitelist kontrolü
		whitelistIPs := w.config.GetStringSlice("security.whitelist_ips")
		isWhitelisted := false
		for _, ip := range whitelistIPs {
			if ip == clientIP {
				isWhitelisted = true
				break
			}
		}

		if !isWhitelisted {
			// Rate limit kontrolü
			if w.checkRateLimit(c) {
				c.AbortWithStatus(http.StatusTooManyRequests)
				return
			}

			// Request size kontrolü
			if c.Request.ContentLength > w.config.GetInt64("security.max_request_size_bytes") {
				log.WithFields(logrus.Fields{
					"ip":   clientIP,
					"size": c.Request.ContentLength,
				}).Warn("Maksimum istek boyutu aşıldı")
				c.AbortWithStatus(http.StatusRequestEntityTooLarge)
				return
			}

			// Güvenlik kontrolleri
			if isAttack, attackType, pattern := w.checkRequest(c); isAttack {
				log.WithFields(logrus.Fields{
					"ip":         clientIP,
					"type":       attackType,
					"pattern":    pattern,
					"url":        c.Request.URL.String(),
					"method":     c.Request.Method,
					"user_agent": c.Request.UserAgent(),
					"referer":    c.Request.Referer(),
				}).Warn("Saldırı denemesi tespit edildi")
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		// Güvenlik kontrollerinden geçti
		c.Status(http.StatusOK)

		// Request/Response logla
		duration := time.Since(startTime)
		log.WithFields(logrus.Fields{
			"ip":          clientIP,
			"method":      c.Request.Method,
			"url":         c.Request.URL.String(),
			"status":      c.Writer.Status(),
			"duration_ms": duration.Milliseconds(),
			"user_agent":  c.Request.UserAgent(),
			"referer":     c.Request.Referer(),
		}).Info("Request tamamlandı")
	}
}

func main() {
	waf, err := NewWAF()
	if err != nil {
		log.Fatal(err)
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(waf.Middleware())

	port := waf.config.GetString("server.port")
	log.Infof("WAF %s portunda başlatılıyor...", port)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  waf.config.GetDuration("server.read_timeout"),
		WriteTimeout: waf.config.GetDuration("server.write_timeout"),
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

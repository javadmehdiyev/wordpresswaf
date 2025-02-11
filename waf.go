package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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

// SQL Injection regex patterns
var sqlInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(union[\s\+]+select|select.+from|insert[\s\+]+into|delete[\s\+]+from|drop[\s\+]+table|drop[\s\+]+database|truncate[\s\+]+table|update[\s\+]+set)`),
	regexp.MustCompile(`(?i)(exec[\s\+]+xp_|exec[\s\+]+sp_|waitfor[\s\+]+delay|benchmark[\s\+]*?\()`),
	regexp.MustCompile(`(?i)(;[\s\+]*?shutdown|;[\s\+]*?drop|--[\s\+]*?|#[\s\+]*?|\/\*(!)?|\*\/)`),
	regexp.MustCompile(`(?i)(cast[\s\+]*?\(|convert[\s\+]*?\(|declare[\s\+]*?@|varchar[\s\+]*?\()`),
	regexp.MustCompile(`(?i)(select.*?case.*?when|select.*?if[\s\+]*?\(|select.*?char[\s\+]*?\()`),
}

// XSS regex patterns
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(<script[^>]*>[\s\S]*?<\/script>)`),
	regexp.MustCompile(`(?i)(javascript:|vbscript:|expression[\s\+]*?\(|applet[\s\+]*?|meta[\s\+]*?|xml[\s\+]*?|blink[\s\+]*?|link[\s\+]*?|style[\s\+]*?|embed[\s\+]*?|object[\s\+]*?|iframe[\s\+]*?|frame[\s\+]*?|frameset[\s\+]*?|ilayer[\s\+]*?|layer[\s\+]*?|bgsound[\s\+]*?|base[\s\+]*?)`),
	regexp.MustCompile(`(?i)(onabort|onactivate|onafterprint|onafterupdate|onbeforeactivate|onbeforecopy|onbeforecut|onbeforedeactivate|onbeforeeditfocus|onbeforepaste|onbeforeprint|onbeforeunload|onbeforeupdate|onblur|onbounce|oncellchange|onchange|onclick|oncontextmenu|oncontrolselect|oncopy|oncut|ondataavailable|ondatasetchanged|ondatasetcomplete|ondblclick|ondeactivate|ondrag|ondragend|ondragenter|ondragleave|ondragover|ondragstart|ondrop|onerror|onerrorupdate|onfilterchange|onfinish|onfocus|onfocusin|onfocusout|onhelp|onkeydown|onkeypress|onkeyup|onlayoutcomplete|onload|onlosecapture|onmousedown|onmouseenter|onmouseleave|onmousemove|onmouseout|onmouseover|onmouseup|onmousewheel|onmove|onmoveend|onmovestart|onpaste|onpropertychange|onreadystatechange|onreset|onresize|onresizeend|onresizestart|onrowenter|onrowexit|onrowsdelete|onrowsinserted|onscroll|onselect|onselectionchange|onselectstart|onstart|onstop|onsubmit|onunload)`),
	regexp.MustCompile(`(?i)(alert|confirm|prompt|eval|execscript|expression|msgbox|refresh|url|void|window\.|\[|\])`),
}

// Path Traversal regex patterns
var pathTraversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af|%uff0e%uff0e%u2215|%uff0e%uff0e%u2216)`),
	regexp.MustCompile(`(?i)((\/|\\)(etc|usr|home|var|root|windows|system|system32|boot|proc))`),
	regexp.MustCompile(`(?i)(\.htaccess|passwd|shadow|master\.mdf|web\.config)`),
}

// WordPress specific attack patterns
var wordpressPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(wp-config\.php|wp-admin|wp-login\.php|xmlrpc\.php|wp-content\/plugins\/|wp-content\/themes\/)`),
	regexp.MustCompile(`(?i)(eval-stdin\.php|wp-load\.php|wp-settings\.php|wp-cron\.php|wp-blog-header\.php)`),
	regexp.MustCompile(`(?i)(wp-json\/|wp\/v2\/|akismet\/|wordfence\/|yoast\/)`),
}

// Shell command injection patterns
var shellInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)([;&\|` + "`" + `][\s]*?(ping|nslookup|traceroute|wget|curl|nc|netcat|bash|sh|python|perl|ruby|php|nmap))`),
	regexp.MustCompile(`(?i)(system|exec|shell_exec|passthru|eval|assert|str_rot13|base64_decode)`),
}

// File upload patterns
var fileUploadPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.(php|phtml|php3|php4|php5|php7|pht|phar|inc)$`),
	regexp.MustCompile(`(?i)\.(asp|aspx|config|ashx|asmx|aspq|axd|cshtm|cshtml|rem|soap|vbhtm|vbhtml|asa|cer|shtml)$`),
	regexp.MustCompile(`(?i)\.(jsp|jspx|jsw|jsv|jspf|wss|do|action)$`),
	regexp.MustCompile(`(?i)\.(cfm|cfml|cfc|dbm)$`),
}

type WAF struct {
	config    *viper.Viper
	rateLimit map[string]int
}

func init() {
	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
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
	// Original URI'yi al
	originalURI := c.GetHeader("X-Original-URI")
	if originalURI == "" {
		originalURI = c.Request.URL.String()
	}

	// Request body'sini oku
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(c.Request.Body)
		// Body'i geri yükle
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Tüm payload'ları birleştir
	payload := fmt.Sprintf("%s %s %s %s %s",
		originalURI,
		c.Request.Method,
		c.Request.UserAgent(),
		string(bodyBytes),
		c.Request.Referer(),
	)

	// Headers'ı ekle
	for key, values := range c.Request.Header {
		payload += " " + key + ": " + strings.Join(values, " ")
	}

	// Payload'ı decode et
	decodedPayload := w.decodePayload(payload)

	// SQL Injection kontrolü
	if found, pattern := w.checkPayload(sqlInjectionPatterns, decodedPayload); found {
		return true, "SQL Injection", pattern
	}

	// XSS kontrolü
	if found, pattern := w.checkPayload(xssPatterns, decodedPayload); found {
		return true, "XSS", pattern
	}

	// Path Traversal kontrolü
	if found, pattern := w.checkPayload(pathTraversalPatterns, decodedPayload); found {
		return true, "Path Traversal", pattern
	}

	// Shell injection kontrolü
	if found, pattern := w.checkPayload(shellInjectionPatterns, decodedPayload); found {
		return true, "Shell Injection", pattern
	}

	// File upload kontrolü
	if c.Request.Method == "POST" && c.Request.Header.Get("Content-Type") != "" {
		if strings.Contains(c.Request.Header.Get("Content-Type"), "multipart/form-data") {
			if found, pattern := w.checkPayload(fileUploadPatterns, decodedPayload); found {
				return true, "Malicious File Upload", pattern
			}
		}
	}

	// WordPress specific kontroller
	if found, pattern := w.checkPayload(wordpressPatterns, decodedPayload); found {
		// WordPress endpoint'lerini sadece logla
		log.WithFields(logrus.Fields{
			"ip":      c.ClientIP(),
			"type":    "WordPress Endpoint",
			"pattern": pattern,
			"url":     originalURI,
		}).Info("WordPress endpoint erişimi")
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

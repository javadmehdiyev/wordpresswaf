# WordPress Web Application Firewall (WAF)

Bu proje, WordPress siteleri için Go dilinde yazılmış profesyonel bir Web Application Firewall (WAF) uygulamasıdır. Nginx ile entegre çalışarak WordPress sitenizi çeşitli saldırılara karşı korur.

## Özellikler

- SQL Injection koruması
- XSS (Cross-Site Scripting) koruması
- Path Traversal koruması
- Shell injection koruması
- IP tabanlı rate limiting
- IP bazlı blacklisting/whitelisting
- Zararlı User-Agent engelleme
- WordPress'e özel güvenlik kuralları
- Detaylı JSON formatında loglama
- Nginx auth_request modülü ile entegrasyon
- Yüksek performanslı Go implementasyonu

## Sistem Gereksinimleri

- Go 1.16 veya üzeri
- Nginx (auth_request modülü ile)
- PHP-FPM
- WordPress kurulumu

## Kurulum Adımları

### 1. Gerekli Paketlerin Kurulumu

```bash
# Nginx ve PHP-FPM kurulumu
sudo apt update
sudo apt install nginx php-fpm

# Nginx auth_request modülünün kurulumu
sudo apt install nginx-extras
```

### 2. WAF Kurulumu

```bash
# Projeyi klonlayın
git clone https://github.com/yourusername/waf.git
cd waf

# Bağımlılıkları yükleyin
go mod download

# Uygulamayı derleyin
go build
```

### 3. Konfigürasyon

1. `config.yaml` dosyasını düzenleyin:
```bash
cp config.yaml.example config.yaml
nano config.yaml
```

2. Önemli ayarlar:
   - `server.port`: WAF'ın çalışacağı port (varsayılan: 8080)
   - `security.rate_limit`: Rate limiting ayarları
   - `security.blocked_ips`: Engellenecek IP'ler
   - `security.whitelist_ips`: İzin verilen IP'ler
   - `logging`: Log ayarları

### 4. Nginx Konfigürasyonu

1. WordPress site konfigürasyonunu oluşturun:
```bash
sudo nano /etc/nginx/sites-available/wordpress
```

2. Aşağıdaki konfigürasyonu ekleyin:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/html/wordpress/public_html;
    index index.php;

    # WAF'a yönlendir
    location / {
        # WAF'ı kontrol et
        auth_request /waf-check;
        
        # WAF'tan geçerse normal işleme devam et
        try_files $uri $uri/ /index.php?$args;
    }

    # WAF kontrol endpoint'i
    location = /waf-check {
        internal;
        proxy_pass http://localhost:8080;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # PHP dosyalarını işle
    location ~ \.php$ {
        # WAF'ı kontrol et
        auth_request /waf-check;
        
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    # WordPress özel kurallar
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    location ~* \.(css|gif|ico|jpeg|jpg|js|png)$ {
        expires max;
        log_not_found off;
    }
}
```

3. Nginx konfigürasyonunu etkinleştirin:
```bash
sudo ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 5. WAF'ı Çalıştırma

1. WAF'ı başlatın:
```bash
./waf
```

2. Servis olarak çalıştırmak için systemd service dosyası oluşturun:
```bash
sudo nano /etc/systemd/system/waf.service
```

3. Service dosyasına ekleyin:
```ini
[Unit]
Description=WordPress Web Application Firewall
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/waf
ExecStart=/path/to/waf/waf
Restart=always

[Install]
WantedBy=multi-user.target
```

4. Servisi etkinleştirin ve başlatın:
```bash
sudo systemctl enable waf
sudo systemctl start waf
```

## Log İzleme

WAF loglarını izlemek için:
```bash
tail -f waf.log
```

JSON formatındaki logları daha okunabilir hale getirmek için:
```bash
tail -f waf.log | jq
```

## Güvenlik Ayarları

### IP Engelleme
`config.yaml` dosyasında `security.blocked_ips` altına engellemek istediğiniz IP'leri ekleyin:
```yaml
security:
  blocked_ips:
    - "1.2.3.4"
    - "5.6.7.8"
```

### Rate Limiting
İstek limitlerini ayarlamak için:
```yaml
security:
  rate_limit:
    requests: 100    # maksimum istek sayısı
    per_seconds: 60  # süre (saniye)
```

### Zararlı User-Agent'ları Engelleme
`security.blocked_user_agents` altına engellemek istediğiniz user-agent'ları ekleyin:
```yaml
security:
  blocked_user_agents:
    - "(?i)sqlmap"
    - "(?i)nikto"
```

## Sorun Giderme

1. WAF loglarını kontrol edin:
```bash
tail -f waf.log
```

2. Nginx error loglarını kontrol edin:
```bash
sudo tail -f /var/log/nginx/error.log
```

3. PHP-FPM loglarını kontrol edin:
```bash
sudo tail -f /var/log/php-fpm/www-error.log
```

## Güvenlik Tavsiyeleri

1. WAF'ı root olmayan bir kullanıcı ile çalıştırın
2. Whitelist yaklaşımını kullanın
3. Rate limiting değerlerini sitenizin trafiğine göre ayarlayın
4. Düzenli olarak logları kontrol edin
5. WordPress'i güncel tutun
6. Güvenlik güncellemelerini düzenli olarak yapın

## Lisans

MIT License

## Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun 
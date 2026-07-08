package fingerprint

func BuiltinRules() []Rule {
	return []Rule{
		{
			Name:       "Nginx",
			Category:   "Middleware",
			Risk:       RiskInfo,
			Tags:       []string{"web-server"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "header", Key: "Server", Contains: "nginx"},
			},
		},
		{
			Name:       "Apache HTTP Server",
			Category:   "Middleware",
			Risk:       RiskInfo,
			Tags:       []string{"web-server"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "header", Key: "Server", Contains: "Apache"},
			},
		},
		{
			Name:       "Microsoft IIS",
			Category:   "Middleware",
			Risk:       RiskInfo,
			Tags:       []string{"web-server", "windows"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "header", Key: "Server", Contains: "Microsoft-IIS"},
				{Type: "header", Key: "X-Powered-By", Contains: "ASP.NET"},
			},
		},
		{
			Name:       "Apache Tomcat",
			Category:   "Middleware",
			Risk:       RiskMedium,
			Tags:       []string{"java", "admin-surface"},
			Confidence: 85,
			Matchers: []Matcher{
				{Type: "header", Key: "Server", Contains: "Apache-Coyote"},
				{Type: "body", Contains: "Apache Tomcat"},
				{Type: "title", Contains: "Apache Tomcat"},
				{Type: "path", Contains: "/manager/"},
			},
		},
		{
			Name:       "WordPress",
			Category:   "CMS",
			Risk:       RiskLow,
			Tags:       []string{"php", "cms"},
			Confidence: 85,
			Matchers: []Matcher{
				{Type: "body", Contains: "wp-content"},
				{Type: "body", Contains: "wp-includes"},
				{Type: "path", Contains: "wp-login.php"},
			},
		},
		{
			Name:       "Discuz",
			Category:   "CMS",
			Risk:       RiskLow,
			Tags:       []string{"php", "cms"},
			Confidence: 80,
			Matchers: []Matcher{
				{Type: "body", Contains: "Discuz!"},
				{Type: "body", Contains: "discuz_uid"},
			},
		},
		{
			Name:       "Joomla",
			Category:   "CMS",
			Risk:       RiskLow,
			Tags:       []string{"php", "cms"},
			Confidence: 80,
			Matchers: []Matcher{
				{Type: "body", Contains: "content=\"Joomla!"},
				{Type: "body", Contains: "/media/system/js/"},
			},
		},
		{
			Name:       "Drupal",
			Category:   "CMS",
			Risk:       RiskLow,
			Tags:       []string{"php", "cms"},
			Confidence: 80,
			Matchers: []Matcher{
				{Type: "header", Key: "X-Generator", Contains: "Drupal"},
				{Type: "body", Contains: "Drupal.settings"},
			},
		},
		{
			Name:       "ThinkPHP",
			Category:   "Framework",
			Risk:       RiskMedium,
			Tags:       []string{"php", "framework"},
			Confidence: 80,
			Matchers: []Matcher{
				{Type: "header", Key: "X-Powered-By", Contains: "ThinkPHP"},
				{Type: "body", Contains: "ThinkPHP"},
			},
		},
		{
			Name:       "Laravel",
			Category:   "Framework",
			Risk:       RiskLow,
			Tags:       []string{"php", "framework"},
			Confidence: 80,
			Matchers: []Matcher{
				{Type: "header", Key: "Set-Cookie", Contains: "laravel_session"},
				{Type: "body", Contains: "Laravel"},
			},
		},
		{
			Name:       "Django",
			Category:   "Framework",
			Risk:       RiskLow,
			Tags:       []string{"python", "framework"},
			Confidence: 75,
			Matchers: []Matcher{
				{Type: "header", Key: "Set-Cookie", Contains: "csrftoken"},
				{Type: "body", Contains: "csrfmiddlewaretoken"},
			},
		},
		{
			Name:       "Flask",
			Category:   "Framework",
			Risk:       RiskLow,
			Tags:       []string{"python", "framework"},
			Confidence: 70,
			Matchers: []Matcher{
				{Type: "header", Key: "Server", Contains: "Werkzeug"},
				{Type: "body", Contains: "Flask"},
			},
		},
		{
			Name:       "Spring Boot Actuator",
			Category:   "Sensitive Component",
			Risk:       RiskHigh,
			Tags:       []string{"java", "actuator", "exposure"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "path", Contains: "/actuator"},
				{Type: "header", Key: "Content-Type", Contains: "application/vnd.spring-boot.actuator"},
			},
		},
		{
			Name:       "Swagger UI",
			Category:   "Sensitive Component",
			Risk:       RiskMedium,
			Tags:       []string{"api-docs", "exposure"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "title", Contains: "Swagger UI"},
				{Type: "body", Contains: "swagger-ui"},
				{Type: "path", Contains: "swagger"},
				{Type: "path", Contains: "api-docs"},
			},
		},
		{
			Name:       "phpMyAdmin",
			Category:   "Sensitive Component",
			Risk:       RiskHigh,
			Tags:       []string{"php", "database", "admin-surface"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "title", Contains: "phpMyAdmin"},
				{Type: "body", Contains: "pma_password"},
				{Type: "path", Contains: "phpmyadmin"},
			},
		},
		{
			Name:       "Jenkins",
			Category:   "Sensitive Component",
			Risk:       RiskHigh,
			Tags:       []string{"ci", "admin-surface"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "header", Key: "X-Jenkins", Contains: "."},
				{Type: "title", Contains: "Jenkins"},
				{Type: "body", Contains: "jenkins.model.Jenkins"},
			},
		},
		{
			Name:       "Grafana",
			Category:   "Sensitive Component",
			Risk:       RiskMedium,
			Tags:       []string{"monitoring", "admin-surface"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "title", Contains: "Grafana"},
				{Type: "body", Contains: "grafana-app"},
			},
		},
		{
			Name:       "Nacos",
			Category:   "Sensitive Component",
			Risk:       RiskHigh,
			Tags:       []string{"java", "config-center", "admin-surface"},
			Confidence: 90,
			Matchers: []Matcher{
				{Type: "title", Contains: "Nacos"},
				{Type: "body", Contains: "nacos"},
				{Type: "path", Contains: "/nacos/"},
			},
		},
		{
			Name:       "Git Metadata Exposure",
			Category:   "Sensitive File",
			Risk:       RiskHigh,
			Tags:       []string{"source-leak", "exposure"},
			Confidence: 95,
			Matchers: []Matcher{
				{Type: "path", Contains: "/.git/"},
			},
		},
		{
			Name:       "Environment File Exposure",
			Category:   "Sensitive File",
			Risk:       RiskCritical,
			Tags:       []string{"secret", "config-leak"},
			Confidence: 95,
			Matchers: []Matcher{
				{Type: "path", Contains: "/.env"},
				{Type: "body", Contains: "APP_KEY="},
				{Type: "body", Contains: "DB_PASSWORD="},
			},
		},
	}
}

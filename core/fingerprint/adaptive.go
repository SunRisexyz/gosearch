package fingerprint

import "strings"

var adaptivePaths = map[string][]string{
	"Apache Tomcat": {
		"manager/html",
		"manager/status",
		"host-manager/html",
		"docs/",
		"examples/",
	},
	"WordPress": {
		"wp-admin/",
		"wp-json/",
		"xmlrpc.php",
		"wp-content/uploads/",
		"wp-content/debug.log",
	},
	"Discuz": {
		"admin.php",
		"uc_server/admin.php",
		"config/config_global.php.bak",
	},
	"Joomla": {
		"administrator/",
		"configuration.php",
		"configuration.php.bak",
	},
	"Drupal": {
		"user/login",
		"CHANGELOG.txt",
		"sites/default/files/",
	},
	"ThinkPHP": {
		"index.php?s=/index/think\\app/invokefunction",
		"index.php?s=captcha",
		"runtime/log/",
	},
	"Laravel": {
		".env",
		"storage/logs/laravel.log",
		"_ignition/execute-solution",
	},
	"Spring Boot Actuator": {
		"actuator/",
		"actuator/env",
		"actuator/heapdump",
		"actuator/logfile",
		"actuator/mappings",
		"actuator/prometheus",
	},
	"Swagger UI": {
		"swagger-ui/",
		"swagger-ui.html",
		"swagger/index.html",
		"v2/api-docs",
		"v3/api-docs",
		"openapi.json",
	},
	"phpMyAdmin": {
		"phpmyadmin/",
		"phpMyAdmin/",
		"pma/",
		"dbadmin/",
	},
	"Jenkins": {
		"jenkins/",
		"script/",
		"manage/",
		"login/",
		"computer/",
	},
	"Grafana": {
		"login/",
		"api/health",
		"public/build/manifest.json",
	},
	"Nacos": {
		"nacos/",
		"nacos/v1/auth/users",
		"nacos/v1/console/server/state",
	},
}

func AdaptivePaths(findings []Finding) []string {
	seen := make(map[string]struct{})
	paths := make([]string, 0)
	for _, finding := range findings {
		for _, p := range adaptivePaths[finding.Name] {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			key := strings.ToLower(p)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			paths = append(paths, p)
		}
	}
	return paths
}

package scanner

import "testing"

func TestBackupVariantsForFile(t *testing.T) {
	variants := backupVariants("https://example.com/app/config.php", 20)
	want := map[string]struct{}{
		"app/config.php.bak": {},
		"app/config.php~":    {},
		"app/config.bak.php": {},
	}
	for value := range want {
		if !containsString(variants, value) {
			t.Fatalf("variants = %#v, missing %s", variants, value)
		}
	}
}

func TestBackupVariantsForDirectory(t *testing.T) {
	variants := backupVariants("https://example.com/admin/", 20)
	want := map[string]struct{}{
		"admin.zip": {},
		"admin.bak": {},
		"admin~":    {},
	}
	for value := range want {
		if !containsString(variants, value) {
			t.Fatalf("variants = %#v, missing %s", variants, value)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

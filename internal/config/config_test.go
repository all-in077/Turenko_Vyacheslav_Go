package config

import "testing"

// env превращает map в функцию-«окружение» для load.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":8080" || c.RateLimitRPS != 10 || c.RateLimitBurst != 20 {
		t.Errorf("неверные значения по умолчанию: %+v", c)
	}
	if c.DatabaseURL != "" || c.APIKey != "" || c.TLSEnabled() {
		t.Errorf("защита и база должны быть выключены по умолчанию: %+v", c)
	}
}

func TestLoadValues(t *testing.T) {
	c, err := load(env(map[string]string{
		"HTTP_ADDR":        ":9000",
		"DATABASE_URL":     "postgres://x",
		"API_KEY":          "k",
		"RATE_LIMIT_RPS":   "2.5",
		"RATE_LIMIT_BURST": "7",
		"TLS_CERT_FILE":    "c.pem",
		"TLS_KEY_FILE":     "k.pem",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":9000" || c.DatabaseURL != "postgres://x" || c.APIKey != "k" ||
		c.RateLimitRPS != 2.5 || c.RateLimitBurst != 7 || !c.TLSEnabled() {
		t.Errorf("неверно разобрали: %+v", c)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]map[string]string{
		"rps не число":         {"RATE_LIMIT_RPS": "быстро"},
		"rps отрицательный":    {"RATE_LIMIT_RPS": "-1"},
		"burst не целый":       {"RATE_LIMIT_BURST": "1.5"},
		"burst меньше единицы": {"RATE_LIMIT_BURST": "0"},
		"сертификат без ключа": {"TLS_CERT_FILE": "c.pem"},
		"ключ без сертификата": {"TLS_KEY_FILE": "k.pem"},
	}
	for name, vars := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := load(env(vars)); err == nil {
				t.Error("ожидали ошибку")
			}
		})
	}
}

func TestRateLimitCanBeDisabled(t *testing.T) {
	c, err := load(env(map[string]string{"RATE_LIMIT_RPS": "0"}))
	if err != nil || c.RateLimitRPS != 0 {
		t.Errorf("rps=0 должен быть допустим: %+v, %v", c, err)
	}
}

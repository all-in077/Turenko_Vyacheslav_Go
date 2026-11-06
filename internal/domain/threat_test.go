package domain

import (
	"errors"
	"strings"
	"testing"
)

const (
	okMD5    = "d41d8cd98f00b204e9800998ecf8427e"
	okSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func ptr[T any](v T) *T { return &v }

func TestParseMD5(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"нормальный хеш", okMD5, okMD5, false},
		{"верхний регистр приводится к нижнему", strings.ToUpper(okMD5), okMD5, false},
		{"пустая строка", "", "", true},
		{"слишком короткий", okMD5[:31], "", true},
		{"слишком длинный", okMD5 + "0", "", true},
		{"не hex-символ", "g41d8cd98f00b204e9800998ecf8427e", "", true},
		{"пробелы по краям не прощаем", " " + okMD5, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMD5(tc.in)
			if tc.wantErr {
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("ожидали *ValidationError, получили %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, err %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	valid := Threat{MD5: okMD5, Name: "Trojan.Win32.Generic"}

	tests := []struct {
		name     string
		mutate   func(*Threat)
		wantProb string // подстрока ожидаемой проблемы; пусто — ждём успех
	}{
		{"минимально валидная угроза", func(*Threat) {}, ""},
		{"все поля заполнены", func(th *Threat) {
			th.SHA256 = okSHA256
			th.Type = "trojan"
			th.Severity = "high"
			th.FileSize = ptr(int64(0)) // ноль — допустимое значение
			th.Description = "что-то плохое"
		}, ""},
		{"плохой md5", func(th *Threat) { th.MD5 = "zzz" }, "md5:"},
		{"пустое имя", func(th *Threat) { th.Name = "" }, "name: is required"},
		{"слишком длинное имя", func(th *Threat) { th.Name = strings.Repeat("я", MaxNameLen+1) }, "name:"},
		{"имя ровно в лимит (считаем руны, а не байты)", func(th *Threat) { th.Name = strings.Repeat("я", MaxNameLen) }, ""},
		{"плохой sha256", func(th *Threat) { th.SHA256 = okMD5 }, "sha256:"},
		{"неизвестный type", func(th *Threat) { th.Type = "virusoid" }, "type:"},
		{"неизвестный severity", func(th *Threat) { th.Severity = "extreme" }, "severity:"},
		{"type в верхнем регистре не принимаем", func(th *Threat) { th.Type = "Trojan" }, "type:"},
		{"отрицательный размер", func(th *Threat) { th.FileSize = ptr(int64(-1)) }, "file_size:"},
		{"слишком длинное описание", func(th *Threat) { th.Description = strings.Repeat("a", MaxDescriptionLen+1) }, "description:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			th := valid
			tc.mutate(&th)
			err := th.Validate()
			if tc.wantProb == "" {
				if err != nil {
					t.Fatalf("неожиданная ошибка: %v", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("ожидали *ValidationError, получили %v", err)
			}
			if !strings.Contains(ve.Error(), tc.wantProb) {
				t.Fatalf("в ошибке %q нет %q", ve.Error(), tc.wantProb)
			}
		})
	}
}

func TestValidateCollectsAllProblems(t *testing.T) {
	err := Threat{MD5: "bad", Name: "", Severity: "nope"}.Validate()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ожидали *ValidationError, получили %v", err)
	}
	if len(ve.Problems) != 3 {
		t.Fatalf("ожидали 3 проблемы сразу, получили %d: %v", len(ve.Problems), ve.Problems)
	}
}

func TestNormalize(t *testing.T) {
	th := Threat{
		MD5:         strings.ToUpper(okMD5),
		SHA256:      strings.ToUpper(okSHA256),
		Name:        "  Trojan  ",
		Description: "\n описание \t",
	}
	th.Normalize()

	if th.MD5 != okMD5 || th.SHA256 != okSHA256 {
		t.Errorf("хеши не приведены к нижнему регистру: %q %q", th.MD5, th.SHA256)
	}
	if th.Name != "Trojan" || th.Description != "описание" {
		t.Errorf("пробелы не убраны: %q %q", th.Name, th.Description)
	}
}

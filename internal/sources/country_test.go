package sources

import (
	"testing"
)

func TestIsRussianEgress(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		payload string
		want    bool
	}{
		{
			name:    "Russian flag emoji",
			label:   "2027 | 🇷🇺 Russia | VLESS | TG: @YoutubeUnBlockRu",
			payload: "vless://id@31.128.36.48:443?security=reality",
			want:    true,
		},
		{
			name:    "Russian RU marker",
			label:   "🇷🇺 RU | CIDR | 196 | @ByeWhiteLists2",
			payload: "vless://id@1.2.3.4:443?security=reality",
			want:    true,
		},
		{
			name:    "Beget hosting in payload",
			label:   "Unlabelled Server",
			payload: "vless://id@server1.beget.tech:443?security=reality",
			want:    true,
		},
		{
			name:    ".ru TLD in payload",
			label:   "Custom Node",
			payload: "vless://id@vpn.myhost.ru:443?security=reality",
			want:    true,
		},
		{
			name:    "German server",
			label:   "6140 | 🇩🇪 Germany | VLESS | 📺 YT | TG: @YoutubeUnBlockRu",
			payload: "vless://id@194.48.217.164:443?security=reality",
			want:    false,
		},
		{
			name:    "UK server",
			label:   "7092 | 🇬🇧 United Kingdom | VLESS | 📺 YT | TG: @YoutubeUnBlockRu",
			payload: "vless://id@18.169.49.13:22224?security=reality",
			want:    false,
		},
		{
			name:    "Netherlands server",
			label:   "🇳🇱 The Netherlands, Amsterdam | [BL]",
			payload: "vless://id@45.15.15.15:443?security=reality",
			want:    false,
		},
		{
			name:    "Poland server",
			label:   "🇵🇱 Poland, Warsaw | [BL]",
			payload: "vless://id@91.200.200.200:443?security=reality",
			want:    false,
		},
		{
			name:    "CIDR-Yandex in label",
			label:   "8086 | 🌐 Unknown | 🏳️ CIDR-Yandex | VLESS | TG: @YoutubeUnBlockRu",
			payload: "vless://id@1.2.3.4:443?security=reality",
			want:    true,
		},
		{
			name:    "CIDR-VK in label",
			label:   "5818 | 🇷🇺 Russia | 🏳️ CIDR-VK | 🏳️ SNI-MAX | VLESS | TG: @YoutubeUnBlockRu",
			payload: "vless://id@1.2.3.4:443?security=reality",
			want:    true,
		},
		{
			name:    "CIDR-Regru in label",
			label:   "6785 | 🇷🇺 Russia | 🏳️ CIDR-Regru | VLESS | TG: @YoutubeUnBlockRu",
			payload: "vless://id@1.2.3.4:443?security=reality",
			want:    true,
		},
		{
			name:    "Russian Cyrillic label",
			label:   "🇷🇺 Россия | YouTube",
			payload: "vless://id@1.2.3.4:443?security=reality",
			want:    true,
		},
		{
			name:    "mcufa.pro in payload",
			label:   "8086 | 🌐 Unknown | VLESS | TG: @YoutubeUnBlockRu",
			payload: "vless://id@xs14.mcufa.pro:443?security=reality",
			want:    true,
		},
		{
			name:    "Netherlands server with SNI-Yandex masquerade is NOT Russian egress",
			label:   "7086 | 🇳🇱 Netherlands | 🏳️ SNI-Yandex | VLESS | 📺 YT | TG: @YoutubeUnBlockRu",
			payload: "vless://id@45.15.15.15:443?security=reality",
			want:    false,
		},
		{
			name:    "Latvia server with SNI-VK masquerade is NOT Russian egress",
			label:   "4151 | 🇱🇻 Latvia | 🏳️ SNI-VK | VLESS | 📺 YT | 🔐 Stable | TG: @YoutubeUnBlockRu",
			payload: "vless://id@45.15.15.15:443?security=reality",
			want:    false,
		},
		{
			name:    "Finland server with SNI-DZEN masquerade is NOT Russian egress",
			label:   "1644 | 🇫🇮 Finland | 🏳️ SNI-DZEN | VLESS | 📺 YT | TG: @YoutubeUnBlockRu",
			payload: "vless://id@45.15.15.15:443?security=reality",
			want:    false,
		},
		{
			name:    "Czechia server with CIDR-OLD is NOT Russian egress",
			label:   "6485 | 🇨🇿 Czechia | 🏳️ CIDR-OLD | VLESS | 📺 YT | TG: @YoutubeUnBlockRu",
			payload: "vless://id@45.15.15.15:443?security=reality",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRussianEgress(tt.label, tt.payload); got != tt.want {
				t.Errorf("IsRussianEgress(%q, %q) = %v, want %v", tt.label, tt.payload, got, tt.want)
			}
		})
	}
}

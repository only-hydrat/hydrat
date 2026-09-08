package sources

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	ruCIDRMarkers = []string{
		"cidr-yandex", "cidr-vk", "cidr-regru", "cidr-ihc", "cidr-selectel",
		"cidr-mts", "cidr-megafon", "cidr-beeline", "cidr-rostelecom",
		"cidr-vdsina", "cidr-timeweb", "cidr-sweb",
	}

	ruProviders = []string{
		"selectel", "timeweb", "vdsina", "firstvds", "ihc.ru",
		"rostelecom", "ростелеком", "reg.ru", "beget", "sweb.ru",
	}

	ruCities = []string{
		"moscow", "москва", "saint petersburg", "st. petersburg", "санкт-петербург",
		"питер", "novosibirsk", "новосибирск", "ekaterinburg", "yekaterinburg",
		"екатеринбург", "kazan", "казань", "nizhny novgorod", "нижний новгород",
		"samara", "самара", "omsk", "омск", "chelyabinsk", "челябинск", "rostov",
		"ростов", "ufa", "уфа", "krasnoyarsk", "красноярск", "voronezh", "воронеж",
		"perm", "пермь", "volgograd", "волгоград", "krasnodar", "краснодар",
	}

	sniTagRegex = regexp.MustCompile(`(?i)sni-[^\s|]+`)
)

// IsRussianEgress returns true if a candidate's label or payload indicates
// that the exit node is physically located in the Russian Federation.
func IsRussianEgress(label, payload string) bool {
	// 1. Check label for Russian country indicators (flag, name, or country code)
	labelLower := strings.ToLower(label)
	if strings.Contains(label, "🇷🇺") ||
		strings.Contains(labelLower, "russia") ||
		strings.Contains(labelLower, "россия") ||
		strings.Contains(labelLower, "российская") {
		return true
	}
	for _, marker := range []string{
		" ru ", " ru|", "|ru|", "| ru |", "[ru]", "(ru)", " ru-", "-ru-", " ru/", "/ru/",
		" ru_", "_ru_", " ru:", ":ru:", "ru /", "ru / ", "ru - ",
	} {
		if strings.Contains(labelLower, marker) {
			return true
		}
	}
	if strings.HasPrefix(labelLower, "ru ") || strings.HasPrefix(labelLower, "ru-") ||
		strings.HasPrefix(labelLower, "ru|") || strings.HasPrefix(labelLower, "ru/") {
		return true
	}
	if strings.HasSuffix(labelLower, " ru") || strings.HasSuffix(labelLower, "|ru") ||
		strings.HasSuffix(labelLower, "-ru") || strings.HasSuffix(labelLower, "[ru]") {
		return true
	}

	// Check Russian network/CIDR markers in label (e.g. CIDR-Yandex, CIDR-VK, CIDR-Selectel)
	for _, marker := range ruCIDRMarkers {
		if strings.Contains(labelLower, marker) {
			return true
		}
	}

	// Check provider names in label, excluding SNI masquerade tags (e.g. SNI-Yandex used on foreign nodes)
	labelNoSNI := sniTagRegex.ReplaceAllString(labelLower, "")
	for _, provider := range ruProviders {
		if strings.Contains(labelNoSNI, provider) {
			return true
		}
	}

	// Check Russian cities in label with word boundary delimiters
	for _, city := range ruCities {
		idx := strings.Index(labelLower, city)
		for idx >= 0 {
			before := idx == 0 || isWordDelimiter(rune(labelLower[idx-1]))
			after := idx+len(city) == len(labelLower) || isWordDelimiter(rune(labelLower[idx+len(city)]))
			if before && after {
				return true
			}
			next := strings.Index(labelLower[idx+len(city):], city)
			if next < 0 {
				break
			}
			idx += len(city) + next
		}
	}

	// 2. Check payload hostname/address (only the host, not query params)
	if strings.HasPrefix(payload, "vless://") {
		if parsed, err := url.Parse(payload); err == nil {
			host := strings.ToLower(parsed.Hostname())
			if strings.HasSuffix(host, ".ru") || strings.HasSuffix(host, ".su") || strings.HasSuffix(host, ".xn--p1ai") {
				return true
			}
			for _, ruProvider := range []string{
				"beget", "selectel", "timeweb", "reg.ru", "sweb.ru",
				"vdsina", "firstvds", "ihc.ru", "rostelecom", "megafon", "mts.ru",
				"yandex", "yccdn", "ya.ru", "vk.com", "vkcloud", "mail.ru", "mcufa.pro",
			} {
				if strings.Contains(host, ruProvider) {
					return true
				}
			}
		}
	}

	return false
}

func isWordDelimiter(r rune) bool {
	return r == ' ' || r == '|' || r == '_' || r == '-' || r == '/' || r == ',' ||
		r == '.' || r == ':' || r == ';' || r == '(' || r == ')' || r == '[' || r == ']'
}

package sources

// SuggestedPublicSubscriptions lists the feeds offered in Hydrat’s source picker.
func SuggestedPublicSubscriptions() []PreviewItem {
	const raw = "https://raw.githubusercontent.com/"
	feeds := []struct{ label, file string }{
		{"MhdiTaheri V2rayCollector", "MhdiTaheri/V2rayCollector/main/sub/mix"},
		{"Surfboardv2ray TGParse", "Surfboardv2ray/TGParse/main/splitted/mixed"},
		{"mheidari98 .proxy", "mheidari98/.proxy/main/vless"},
		{"peasoft NoMoreWalls", "peasoft/NoMoreWalls/master/list.txt"},
		{"ermaozi get_subscribe", "ermaozi/get_subscribe/main/subscribe/v2ray.txt"},
		{"roosterkid openproxylist", "roosterkid/openproxylist/main/V2RAY_RAW.txt"},
		{"Kwinshadow TelegramV2rayCollector", "Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt"},
		{"Pawdroid Free-servers", "Pawdroid/Free-servers/main/sub"},
	}
	items := make([]PreviewItem, 0, len(feeds))
	for index, feed := range feeds {
		// Reuse a previously added copy of the URL as an ordinary subscription.
		item := parseRemote(index+1, KindRemoteAuto, raw+feed.file)
		item.Kind, item.Display = KindPublicSubscription, feed.label
		items = append(items, item)
	}
	return items
}

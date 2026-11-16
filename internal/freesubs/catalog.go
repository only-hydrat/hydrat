// Package freesubs discovers public free-subscription feeds on the network and
// turns them into source items the store can import. Feeds are ordinary
// subscription URLs (plain or base64 VLESS lists, including REALITY links),
// so the regular refresher keeps them up to date after import.
package freesubs

// Feed is a public subscription URL.
type Feed struct {
	Label string `yaml:"label" json:"label"`
	URL   string `yaml:"url" json:"url"`
}

// Repository describes a public repository directory that publishes feeds.
// Discovery lists the directory through the GitHub API on every run, so files
// added by the collector appear without a new Hydrat release.
type Repository struct {
	Label string `yaml:"label" json:"label"`
	Owner string `yaml:"owner" json:"owner"`
	Name  string `yaml:"name" json:"name"`
	Path  string `yaml:"path,omitempty" json:"path,omitempty"`
}

// Catalog returns the built-in free-subscription feeds. Each entry was verified
// to answer with parseable VLESS/REALITY links; feeds that stop answering are
// reported by the check pass and never imported silently.
func Catalog() []Feed {
	return []Feed{
		{Label: "MhdiTaheri collector", URL: "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix"},
		{Label: "Surfboardv2ray TGParse", URL: "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed"},
		{Label: "mheidari98 proxy", URL: "https://raw.githubusercontent.com/mheidari98/.proxy/main/vless"},
		{Label: "peasoft NoMoreWalls", URL: "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt"},
		{Label: "ermaozi get_subscribe", URL: "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"},
		{Label: "roosterkid openproxylist", URL: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt"},
		{Label: "Kwinshadow collector", URL: "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt"},
		{Label: "Pawdroid Free-servers", URL: "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"},
	}
}

// Repositories returns the built-in collector repositories whose published
// files are discovered on the fly.
func Repositories() []Repository {
	return []Repository{
		{Label: "MhdiTaheri collector", Owner: "MhdiTaheri", Name: "V2rayCollector", Path: "sub"},
		{Label: "mheidari98 proxy", Owner: "mheidari98", Name: ".proxy"},
		{Label: "Mahdi0024 ProxyCollector", Owner: "Mahdi0024", Name: "ProxyCollector", Path: "sub"},
	}
}

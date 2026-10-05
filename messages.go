package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type ruleText struct {
	title string
	why   string // what the finding means, in plain words
	fix   string // what the server owner should do about it
}

type catalog struct {
	scanning    string
	clean       string
	pressEnter  string
	serverFiles string
	whatToDo    string
	nextSteps   string
	steps       []string
	moved       func(n int, dir string) string
	summary     func(resources, files int, d time.Duration) string
	counts      func(h, m, l int) string
	tags        map[severity]string
	rules       map[string]ruleText
}

var en = &catalog{
	scanning:    "scanning",
	clean:       "no backdoor indicators found, the server looks clean",
	pressEnter:  "press Enter to close",
	serverFiles: "server files",
	whatToDo:    "What to do:",
	nextSteps:   "What to do now",
	steps: []string{
		"Stop the server.",
		"Remove the resources marked above. fxsweep -quarantine <folder> can move the infected files out for you.",
		"Change your txAdmin, database and Discord bot passwords and your Cfx.re license key. The attacker could read all of them.",
		"Check txAdmin's admin list for accounts you did not add.",
		"Download scripts only from their original authors. Leaked scripts are how these backdoors spread.",
	},
	moved: func(n int, dir string) string { return fmt.Sprintf("moved %s to %s", count(n, "file"), dir) },
	summary: func(r, f int, d time.Duration) string {
		return fmt.Sprintf("%s, %s in %s", count(r, "resource"), count(f, "file"), d)
	},
	counts: func(h, m, l int) string { return fmt.Sprintf("%d high, %d medium, %d low", h, m, l) },
	tags:   map[severity]string{high: "HIGH", medium: "MED", low: "LOW"},
	rules: map[string]ruleText{
		"FX001": {"Known backdoor indicator",
			"Contains an address or marker used by a known backdoor panel. This resource is almost certainly infected.",
			"Delete this resource and download it again from its original author."},
		"FX002": {"Downloads and runs remote code",
			"Downloads code from the internet and runs it on your server. Backdoor panels take over servers this way.",
			"Delete this resource and download it again from its original author."},
		"FX003": {"XOR string dropper",
			"Hides its real code by scrambling it and unscrambles it while running. A normal script has no reason to do this.",
			"Delete this resource and download it again from its original author."},
		"FX004": {"Encoded payload",
			"A long text written as escape codes so it cannot be read at a glance. fxsweep decoded it, see the line below. A web address or code here usually means a hidden backdoor.",
			"If you did not write this, delete the resource and download it again from its original author."},
		"FX005": {"Obfuscated code",
			"The code is scrambled so nobody can read it. Some paid scripts do this to protect themselves, backdoors do it to hide.",
			"Keep it only if you bought it from a seller you trust."},
		"FX006": {"Runs shell commands",
			"Can run programs on the server machine itself, outside the game. A FiveM script rarely needs this.",
			"Find out why this script needs it. If nobody can tell you, remove the resource."},
		"FX007": {"txAdmin tampering",
			"txAdmin's own files were changed, or an admin account known from attacks was added. Attackers do this to hide their resources and keep access.",
			"Reinstall FXServer and txAdmin from the official download and change every txAdmin password."},
		"FX008": {"Runs an encoded string",
			"Builds code out of character codes and runs it, so you cannot see what it does by reading the file.",
			"Delete this resource and download it again from its original author."},
		"FX010": {"Hidden script entry in manifest",
			"fxmanifest.lua loads a hidden file. A common trick is to comment out the real line and slip a hidden script onto the same line.",
			"Restore the original fxmanifest.lua and delete the hidden file."},
		"FX011": {"Suspicious script path in manifest",
			"fxmanifest.lua loads a script from a place where droppers like to hide.",
			"Open that file and check it. If you did not add it, delete it."},
		"FX012": {"Known dropper file name",
			"This file name is used by the Blum Panel dropper. With loader code inside it is high severity, otherwise check it by hand.",
			"Delete this resource and download it again from its original author."},
		"FX020": {"Discord webhook sent to players",
			"Every player downloads this file, so anyone can copy the webhook and spam or delete your Discord channel.",
			"Move the webhook into a server script, then delete it in Discord and create a new one. The old one is already public."},
		"FX021": {"Database credentials sent to players",
			"Every player downloads this file, so anyone can read your database login.",
			"Move the connection details into server.cfg and change the database password."},
		"FX030": {"RCON enabled",
			"RCON sends its password over the network in plain text and is an easy way in.",
			"Remove rcon_password from server.cfg. txAdmin already gives you a console."},
		"FX031": {"Every player can run every command",
			"Anyone who joins the server can run every command, admin commands included.",
			"Delete this line from server.cfg and give command access only to your admin group."},
	},
}

var tr = &catalog{
	scanning:    "taranıyor:",
	clean:       "arka kapı izi bulunamadı, sunucu temiz görünüyor",
	pressEnter:  "kapatmak için Enter'a bas",
	serverFiles: "sunucu dosyaları",
	whatToDo:    "Ne yapmalı:",
	nextSteps:   "Şimdi ne yapmalı",
	steps: []string{
		"Sunucuyu kapat.",
		"Yukarıda işaretlenen scriptleri kaldır. fxsweep -quarantine <klasör> virüslü dosyaları senin yerine kenara taşıyabilir.",
		"txAdmin, veritabanı ve Discord bot şifrelerini ve Cfx.re lisans anahtarını değiştir. Saldırgan hepsini okuyabilirdi.",
		"txAdmin yönetici listesinde senin eklemediğin hesap var mı bak.",
		"Scriptleri sadece asıl geliştiricisinden indir. Bu arka kapılar sızdırılmış (leak) scriptlerle yayılıyor.",
	},
	moved: func(n int, dir string) string { return fmt.Sprintf("%d dosya %s klasörüne taşındı", n, dir) },
	summary: func(r, f int, d time.Duration) string {
		return fmt.Sprintf("%d script, %d dosya, %s", r, f, d)
	},
	counts: func(h, m, l int) string { return fmt.Sprintf("%d yüksek, %d orta, %d düşük", h, m, l) },
	tags:   map[severity]string{high: "YÜKSEK", medium: "ORTA", low: "DÜŞÜK"},
	rules: map[string]ruleText{
		"FX001": {"Bilinen arka kapı izi",
			"Bilinen bir arka kapı panelinin adresi ya da izi var. Bu script büyük ihtimalle virüslü.",
			"Scripti sil ve asıl geliştiricisinden yeniden indir."},
		"FX002": {"İnternetten kod indirip çalıştırıyor",
			"İnternetten kod indirip sunucunda çalıştırıyor. Arka kapı panelleri sunucuları bu yolla ele geçirir.",
			"Scripti sil ve asıl geliştiricisinden yeniden indir."},
		"FX003": {"Şifreli zararlı kod",
			"Asıl kodunu karıştırıp gizliyor, çalışırken çözüyor. Normal bir scriptin bunu yapması için sebep yok.",
			"Scripti sil ve asıl geliştiricisinden yeniden indir."},
		"FX004": {"Şifrelenmiş içerik",
			"Bir bakışta okunmasın diye kodlanmış uzun bir yazı var. fxsweep çözdü, alttaki satırda görünüyor. Burada bir internet adresi ya da kod varsa genelde gizli bir arka kapıdır.",
			"Bunu sen yazmadıysan scripti sil ve asıl geliştiricisinden yeniden indir."},
		"FX005": {"Okunamaz hale getirilmiş kod",
			"Kod kimse okuyamasın diye karıştırılmış. Bazı ücretli scriptler kendini korumak için yapar, arka kapılar da saklanmak için.",
			"Sadece güvendiğin bir satıcıdan aldıysan tut."},
		"FX006": {"Bilgisayarda komut çalıştırıyor",
			"Oyunun dışında, sunucu bilgisayarında program çalıştırabiliyor. Bir FiveM scriptinin buna nadiren ihtiyacı olur.",
			"Bu scriptin buna neden ihtiyaç duyduğunu öğren. Kimse açıklayamıyorsa kaldır."},
		"FX007": {"txAdmin'e müdahale",
			"txAdmin'in kendi dosyaları değiştirilmiş ya da saldırılardan bilinen bir yönetici hesabı eklenmiş. Saldırganlar bunu kendi scriptlerini gizlemek ve erişimi kaybetmemek için yapar.",
			"FXServer ve txAdmin'i resmi siteden yeniden kur, bütün txAdmin şifrelerini değiştir."},
		"FX008": {"Şifreli yazıyı kod olarak çalıştırıyor",
			"Kodu karakter numaralarından oluşturup çalıştırıyor, böylece dosyayı okuyarak ne yaptığını göremiyorsun.",
			"Scripti sil ve asıl geliştiricisinden yeniden indir."},
		"FX010": {"Manifestte gizli script",
			"fxmanifest.lua gizli bir dosya yüklüyor. Bilinen hile: gerçek satırı yorum satırı yapıp aynı satırın sonuna gizli bir script eklemek.",
			"Orijinal fxmanifest.lua dosyasını geri koy ve gizli dosyayı sil."},
		"FX011": {"Manifestte şüpheli dosya yolu",
			"fxmanifest.lua, zararlıların saklanmayı sevdiği bir yerden script yüklüyor.",
			"O dosyayı açıp kontrol et. Sen eklemediysen sil."},
		"FX012": {"Bilinen zararlı dosya adı",
			"Bu dosya adını Blum Panel zararlısı kullanıyor. İçinde yükleyici kod varsa ciddi, yoksa elle kontrol et.",
			"Scripti sil ve asıl geliştiricisinden yeniden indir."},
		"FX020": {"Discord webhook'u oyunculara gidiyor",
			"Bu dosya her oyuncunun bilgisayarına iniyor. Herkes webhook'u kopyalayıp Discord kanalına spam atabilir ya da silebilir.",
			"Webhook'u sunucu tarafındaki bir scripte taşı, sonra Discord'da silip yenisini oluştur. Eskisi artık herkese açık."},
		"FX021": {"Veritabanı şifresi oyunculara gidiyor",
			"Bu dosya her oyuncunun bilgisayarına iniyor. Herkes veritabanı giriş bilgilerini okuyabilir.",
			"Bağlantı bilgilerini server.cfg'ye taşı ve veritabanı şifresini değiştir."},
		"FX030": {"RCON açık",
			"RCON şifresini ağ üzerinden açık metin olarak gönderiyor, içeri girmek için kolay bir kapı.",
			"server.cfg'den rcon_password satırını kaldır. txAdmin zaten konsol veriyor."},
		"FX031": {"Her oyuncu her komutu kullanabiliyor",
			"Sunucuya giren herkes bütün komutları, yönetici komutları dahil, kullanabiliyor.",
			"Bu satırı server.cfg'den sil, komut yetkisini sadece yönetici grubuna ver."},
	},
}

var messages = map[string]*catalog{"en": en, "tr": tr}

// detectLang picks Turkish when the system is set to Turkish, English otherwise.
func detectLang() string {
	for _, k := range []string{"FXSWEEP_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := strings.ToLower(os.Getenv(k)); v != "" {
			if strings.HasPrefix(v, "tr") {
				return "tr"
			}
			return "en"
		}
	}
	if systemTurkish() {
		return "tr"
	}
	return "en"
}

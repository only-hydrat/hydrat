# Hydrat для Debian и Ubuntu x86-64

Установите пакет, добавьте свой аккаунт в группу управления Hydrat и войдите в сеанс заново.

```sh
sudo apt install ./hydrat-app_0.1.3_amd64.deb
sudo adduser "$USER" hydrat-users
```

Откройте Hydrat из меню приложений. Добавьте подписки, конфиги VLESS или мосты Tor и нажмите «Подключить». Ядро работает в системной службе `hydrat-app.service`. Закрытие окна оставляет VPN подключённым. Чтобы завершить соединение, нажмите «Отключить».

После запуска Hydrat появляется в области уведомлений. В меню значка видны статус VPN и кнопка «Подключить» или «Отключить». Если панель принимает индикаторы, закрытие окна сворачивает его в трей. В GNOME для значка нужна поддержка AppIndicator, например расширение AppIndicator and KStatusNotifierItem Support.

Пакет рассчитан на Linux с systemd, активным systemd-resolved и устройством `/dev/net/tun`. Группа `hydrat-users` даёт полный доступ к локальному профилю Hydrat и переключению системного VPN. Источники и история проверок хранятся в `/var/lib/hydrat-app`. Журнал доступен через `sudo journalctl -u hydrat-app`.

Выберите язык в **Настройки → Язык**. Он применится при следующем запуске интерфейса. Режим «Автоматически» берёт язык сеанса Linux.

## Сборка

Подготовьте подписанный [Tor Expert Bundle для Linux x86-64](https://www.torproject.org/download/tor/) и совместимые базы проекта `geoip.dat` и `geosite.dat`.

```sh
./scripts/build-app-linux-deb.sh tor-expert-bundle-linux-x86_64.tar.gz ./geo "./hydrat-app_$(cat internal/appupdate/version.txt)_amd64.deb"
```

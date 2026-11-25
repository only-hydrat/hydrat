#!/usr/bin/python3

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import socket
import threading
from tempfile import NamedTemporaryFile
from urllib.parse import quote

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, GLib, Gtk

try:
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as Indicator
except (ImportError, ValueError):
    Indicator = None


APP_DIR = Path(__file__).resolve().parent
SOCKET = "/run/hydrat-app/control.sock"
SUBSCRIPTION_KINDS = {"vless_subscription", "tor_subscription", "remote_auto"}

LANGUAGE_CHOICES = ("", "ru", "en", "zh-CN")
LANGUAGE_FILE = Path(GLib.get_user_config_dir()) / "hydrat-app" / "language"


def saved_language():
    try:
        value = LANGUAGE_FILE.read_text().strip()
    except OSError:
        return ""
    return value if value in LANGUAGE_CHOICES else ""


def detected_language():
    for name in GLib.get_language_names():
        base = re.split(r"[-_.@]", name, maxsplit=1)[0].lower()
        if base in ("ru", "en"):
            return base
        if base == "zh":
            return "zh-CN"
    return "ru"


def load_messages():
    path = APP_DIR / "messages.json"
    if not path.is_file() and len(APP_DIR.parents) >= 2:
        path = APP_DIR.parents[1] / "internal/i18n/catalog/messages.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")).get(saved_language() or detected_language(), {})
    except OSError:
        return {}


MESSAGES = load_messages()


def tr(source, *values):
    message = MESSAGES.get(source, source)
    return message.format(*values) if values else message


def save_language(value):
    LANGUAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=LANGUAGE_FILE.parent, mode="w", delete=False) as pending:
        name = Path(pending.name)
        try:
            pending.write(value + "\n")
            pending.close()
            name.replace(LANGUAGE_FILE)
        finally:
            name.unlink(missing_ok=True)


ISSUE_TEXT = {
    "unsupported source format": tr("ожидается подписка, конфиг VLESS или мост Tor"),
    "invalid VLESS URI": tr("проверьте ссылку VLESS"),
    "invalid subscription URL": tr("проверьте адрес подписки"),
    "invalid Tor bridge line": tr("проверьте строку моста Tor"),
    "unsupported Tor bridge transport": tr("транспорт моста Tor не поддерживается"),
    "source refresh failed": tr("источник сохранён, загрузить ноды не удалось"),
}


class LocalConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class LocalAPI:
    def __init__(self, path):
        self.path = path

    def request(self, method, path, body=None, timeout=95, headers=None):
        with_connection = LocalConnection(self.path, timeout)
        try:
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            with_connection.request(method, path, body, headers or {})
            response = with_connection.getresponse()
            raw = response.read(2 << 20)
            if not raw:
                result = {}
            elif response.headers.get_content_type() == "application/json":
                result = json.loads(raw)
            else:
                result = {}
            if response.status >= 300 or result.get("Error"):
                raise ValueError(tr(result.get("Error") or "Служба Hydrat отклонила запрос."))
            return result
        except PermissionError:
            raise ValueError(tr("Для доступа нужна группа hydrat-users. После добавления в неё войдите в систему заново.")) from None
        except (OSError, http.client.HTTPException):
            raise ValueError(tr("Служба Hydrat недоступна. Проверьте hydrat-app.service.")) from None
        finally:
            with_connection.close()


def box(horizontal=False, gap=10):
    direction = Gtk.Orientation.HORIZONTAL if horizontal else Gtk.Orientation.VERTICAL
    return Gtk.Box(orientation=direction, spacing=gap)


def css(widget, style):
    widget.get_style_context().add_class(style)
    return widget


def label(value="", style=None):
    widget = Gtk.Label(label=value, xalign=0)
    widget.set_line_wrap(True)
    return css(widget, style) if style else widget


def add(parent, child, expand=False):
    parent.pack_start(child, expand, expand, 0)
    return child


def panel(title=None):
    result = css(box(), "panel")
    if title:
        add(result, label(title, "section"))
    return result


def scrolled(widget):
    view = Gtk.ScrolledWindow()
    view.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    view.add(widget)
    return view


def button(text, clicked, style=None):
    result = Gtk.Button(label=text)
    result.connect("clicked", clicked)
    return css(result, style) if style else result


class Window(Gtk.ApplicationWindow):
    def __init__(self, application, api):
        super().__init__(application=application, title="Hydrat")
        self.api = api
        self.status = None
        self.polling = False
        self.busy = False
        self.closing = False
        self.inventory = None
        self.prefs_loaded = False
        self.geo_loaded = False
        self.set_default_size(760, 660)
        self.set_size_request(480, 440)
        css(self, "hydrat")
        root = box(gap=12)
        root.set_border_width(18)
        self.add(root)
        header = add(root, box(horizontal=True, gap=12))
        icon = Gtk.Image.new_from_pixbuf(GdkPixbuf.Pixbuf.new_from_file_at_scale(str(APP_DIR / "icon.png"), 30, 30, True))
        add(header, icon)
        add(header, label("Hydrat", "brand"))
        self.pages = Gtk.Stack()
        self.pages.set_transition_type(Gtk.StackTransitionType.NONE)
        switch = Gtk.StackSwitcher()
        switch.set_stack(self.pages)
        add(header, switch)
        add(root, self.pages, True)
        self.pages.add_titled(scrolled(self.overview()), "home", tr("Главная"))
        self.pages.add_titled(scrolled(self.sources()), "sources", tr("Подключения"))
        self.pages.add_titled(self.settings(), "settings", tr("Настройки"))
        self.pages.connect("notify::visible-child-name", self.page_changed)
        self.tray = self.build_tray()
        self.connect("delete-event", self.close_to_tray)
        self.connect("destroy", self.on_destroy)
        self.show_all()
        self.log_button.hide()
        self.refresh()
        self.timer = GLib.timeout_add_seconds(2, self.refresh)

    def build_tray(self):
        if Indicator is None:
            return None
        self.tray_icon = str(APP_DIR / "icon.png")
        tray = Indicator.Indicator.new("hydrat-vpn", self.tray_icon, Indicator.IndicatorCategory.APPLICATION_STATUS)
        tray.set_title("Hydrat")
        menu = Gtk.Menu()
        self.tray_status = Gtk.MenuItem(label=tr("Загружаем состояние…"), sensitive=False)
        self.tray_action = Gtk.MenuItem(label=tr("Подключить"), sensitive=False)
        self.tray_action.connect("activate", self.toggle)
        show = Gtk.MenuItem(label=tr("Открыть Hydrat"))
        show.connect("activate", lambda _: self.present())
        quit_item = Gtk.MenuItem(label=tr("Закрыть интерфейс"))
        quit_item.connect("activate", lambda _: self.destroy())
        for item in (self.tray_status, self.tray_action, Gtk.SeparatorMenuItem(), show, quit_item):
            menu.append(item)
        menu.show_all()
        tray.set_menu(menu)
        tray.connect("connection-changed", self.tray_connection_changed)
        tray.set_status(Indicator.IndicatorStatus.ACTIVE)
        return tray

    def tray_connection_changed(self, _, connected):
        if not connected and not self.closing and not self.get_visible():
            self.present()

    def close_to_tray(self, *_):
        if self.tray is not None and self.tray.props.connected:
            self.hide()
            return True
        return False

    def on_destroy(self, *_):
        self.closing = True
        if self.tray is not None:
            self.tray.set_status(Indicator.IndicatorStatus.PASSIVE)
        GLib.source_remove(self.timer)

    def request(self, method, path, body=None, *, complete, timeout=95, headers=None):
        def work():
            try:
                result, error = self.api.request(method, path, body, timeout, headers), None
            except (ValueError, TypeError) as exc:
                result, error = None, str(exc)
            GLib.idle_add(deliver, result, error)

        def deliver(result, error):
            if not self.closing:
                complete(result, error)
            return False

        threading.Thread(target=work, daemon=True).start()

    def action(self, method, path, body, message, pending, complete=None, *, headers=None):
        if self.busy:
            return
        self.busy = True
        message.set_text(pending)
        self.render_actions()

        def finished(result, error):
            self.busy = False
            self.render_actions()
            if error:
                message.set_text(error)
            elif complete:
                complete(result)
            self.refresh()

        self.request(method, path, body, complete=finished, headers=headers)

    def refresh(self):
        if self.polling:
            return True
        self.polling = True

        def received(status, error):
            self.polling = False
            self.status = status
            if error:
                self.connection.set_text(tr("Статус VPN недоступен"))
                self.connection_hint.set_text(error)
                self.log_button.show()
                self.render_actions()
                return
            self.render_status(status)

        self.request("GET", "/status", complete=received, timeout=3)
        return True

    def overview(self):
        page = box(gap=12)
        status = add(page, panel())
        self.connection = add(status, label(tr("Загружаем состояние…"), "headline"))
        self.connection_hint = add(status, label(style="muted"))
        self.connection_action = add(status, label(style="muted"))
        actions = add(status, box(horizontal=True))
        self.primary = add(actions, button(tr("Подключить"), self.toggle, "primary"))
        self.log_button = add(actions, button(tr("Журнал службы"), self.open_log))
        routes = add(page, panel(tr("Маршруты")))
        grid = Gtk.Grid(row_spacing=8, column_spacing=18)
        self.routes = {}
        for row, (key, name) in enumerate((("tcp", "TCP"), ("udp", "UDP"), ("tcp_reserve", tr("Резерв TCP")), ("udp_reserve", tr("Резерв UDP")))):
            grid.attach(label(name, "muted"), 0, row, 1, 1)
            self.routes[key] = label(tr("Маршрут не выбран"))
            grid.attach(self.routes[key], 1, row, 1, 1)
        add(routes, grid)
        self.search = add(routes, label(tr("Загружаем состояние…"), "muted"))
        return page

    def open_log(self, _):
        self.connection_action.set_text(tr("Откройте журнал в терминале: sudo journalctl -u hydrat-app"))
        self.connection_action.set_selectable(True)

    def toggle(self, _):
        status = self.status
        if self.busy or status is None or status["Connection"] == "stopping":
            return
        if status["Connection"] == "requested":
            self.action("DELETE", "/connection", None, self.connection_action, tr("Отключаем VPN…"),
                        lambda _: self.connection_action.set_text(""))
        elif status["Sources"] == 0:
            self.present()
            self.pages.set_visible_child_name("sources")
            self.input.grab_focus()
        else:
            self.action("POST", "/connection", None, self.connection_action, tr("Запускаем VPN…"),
                        lambda _: self.connection_action.set_text(""))

    def render_status(self, status):
        connection = status["Connection"]
        tcp, udp = status["TCP"], status["UDP"]
        running = status["Running"]
        searching = status["SearchingSeconds"]
        hint, tone = "", None
        if connection == "failed":
            title, hint, tone = tr("Не удалось запустить VPN"), tr("Подробности в журнале службы Hydrat."), "error"
        elif connection == "stopping":
            title = tr("Отключаем VPN…")
        elif status["Recovering"]:
            title, tone = tr("Восстанавливаем подключение…"), "warning"
        elif tcp and udp:
            title, tone = tr("VPN подключён"), "accent"
        elif tcp:
            title, tone = tr("VPN подключён · UDP недоступен"), "warning"
        elif udp:
            title, tone = tr("VPN подключён · TCP недоступен"), "warning"
        elif not status["Sources"]:
            title, hint = tr("Добавьте источник"), tr("Подойдёт подписка, конфиг VLESS или мост Tor.")
        elif running and searching >= 30:
            title = tr("Рабочий маршрут пока не найден")
        elif running:
            title = tr("Подбираем маршрут…")
        elif connection == "requested":
            title = tr("Запускаем VPN…")
        else:
            title = tr("VPN отключён")
        styles = self.connection.get_style_context()
        for item in ("error", "warning", "accent"):
            styles.remove_class(item)
        if tone:
            styles.add_class(tone)
        self.connection.set_text(title)
        self.connection_hint.set_text(hint)
        self.log_button.set_visible(connection == "failed")
        for role, widget in self.routes.items():
            reserve = "TCPReserveStatus" if role.startswith("tcp") else "UDPReserveStatus"
            widget.set_text(tr("Проверяется") if role.endswith("reserve") and status[reserve] == "checking" else tr("Маршрут не выбран"))
        for node in status.get("Nodes") or ():
            if node["Role"] not in self.routes:
                continue
            parts = [node["Label"] or tr("Маршрут"), node["Protocol"].upper()]
            if node["LatencyMS"]:
                parts.append(tr("{0:.0f} мс", node['LatencyMS']))
            if node["ThroughputMbps"]:
                parts.append(tr("{0:.1f} Мбит/с", node['ThroughputMbps']))
            if node["State"] == "unavailable":
                parts.append(tr("сбой"))
            self.routes[node["Role"]].set_text(" · ".join(filter(None, parts)))
        if running:
            search = status["Search"]
            phase = {"search": tr("Поиск"), "background": tr("Фоновый поиск"), "paused": tr("Пауза"), "waiting": tr("Ожидание")}.get(search["Mode"], tr("Проверки"))
            if search["Workers"]:
                phase += tr(" · потоки: {0}", search['Workers'])
            self.search.set_text(tr("{0} · Проверено {1}/{2} · Готово {3} · Сохранено {4}", phase, status['Checked'], status['Candidates'], status['Qualified'], status['Saved']))
        else:
            self.search.set_text(tr("Нод в каталоге: {0}", status['Candidates']))
        self.render_sources(status.get("Inventory") or [])
        self.render_actions()

    def render_actions(self):
        status = self.status
        connection = status["Connection"] if status else ""
        can_toggle = not self.busy and bool(status) and connection != "stopping"
        self.primary.set_sensitive(can_toggle)
        if status:
            if connection == "requested":
                title = tr("Отключить")
            elif connection == "stopping":
                title = tr("Отключаем…")
            elif not status["Sources"]:
                title = tr("Добавить источник")
            elif connection == "failed":
                title = tr("Подключить снова")
            else:
                title = tr("Подключить")
            self.primary.set_label(title)
        if self.tray is not None:
            state = self.connection.get_text()
            if self.tray_status.get_label() != state:
                self.tray_status.set_label(state)
                self.tray.set_icon_full(self.tray_icon, "Hydrat — " + state)
            self.tray_action.set_label(self.primary.get_label())
            self.tray_action.set_sensitive(can_toggle)
        for widget in (self.import_button, self.suggested, self.refresh_button, self.remove, self.save, self.save_geo):
            widget.set_sensitive(not self.busy and bool(status))
        self.refresh_button.set_sensitive(not self.busy and bool(status and self.inventory))
        row = self.source_list.get_selected_row()
        self.remove.set_sensitive(not self.busy and bool(status and row))
        self.edit_hwid.set_sensitive(not self.busy and bool(status and row and row.source["Kind"] in SUBSCRIPTION_KINDS))
        self.save.set_sensitive(not self.busy and bool(status) and self.prefs_loaded)
        self.save_geo.set_sensitive(not self.busy and bool(status) and self.geo_loaded)
        self.input.set_editable(not self.busy)
        self.import_hwid.set_editable(not self.busy)

    def sources(self):
        page = box(gap=12)
        inventory = add(page, panel(tr("Источники")))
        self.empty = add(inventory, label(tr("Источников пока нет."), "muted"))
        self.source_list = Gtk.ListBox()
        self.source_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.source_list.connect("row-selected", lambda *_: self.render_actions())
        add(inventory, self.source_list)
        inventory_buttons = add(inventory, box(horizontal=True))
        self.refresh_button = add(inventory_buttons, button(tr("Обновить"), self.refresh_sources))
        self.edit_hwid = add(inventory_buttons, button(tr("HWID источника"), self.edit_source_hwid))
        self.remove = add(inventory_buttons, button(tr("Удалить источник"), self.delete_source, "danger"))
        importer = add(page, panel(tr("Добавить источники")))
        add(importer, label(tr("Вставьте ссылки на подписки или конфиги, по одной на строку."), "muted"))
        self.input = Gtk.TextView()
        self.input.set_wrap_mode(Gtk.WrapMode.CHAR)
        view = scrolled(self.input)
        view.set_min_content_height(106)
        add(importer, view)
        self.import_hwid = Gtk.Entry(max_length=64, placeholder_text=tr("Общий HWID"))
        add_field(importer, tr("HWID одной HTTPS-подписки"), self.import_hwid)
        buttons = add(importer, box(horizontal=True))
        self.import_button = add(buttons, button(tr("Импортировать"), self.import_sources, "primary"))
        self.suggested = add(buttons, button(tr("Добавить бесплатные подписки"), self.import_suggested))
        self.source_notice = add(importer, label(style="muted"))
        return page

    def render_sources(self, inventory):
        if inventory == self.inventory:
            return
        selected = self.source_list.get_selected_row()
        selected_id = selected.source["ID"] if selected else None
        self.inventory = inventory
        for item in self.source_list.get_children():
            self.source_list.remove(item)
        for index, item in enumerate(inventory, 1):
            row = Gtk.ListBoxRow()
            row.source = item
            name = item["Label"] or tr("Источник {0}", index)
            state = tr(" · ошибка обновления") if item["Failed"] else ""
            if item.get("CustomHWID"):
                state += tr(" · свой HWID")
            row.add(label(tr("{0} · Ноды: {1}{2}", name, item['Candidates'], state)))
            self.source_list.add(row)
            row.show_all()
            if item["ID"] == selected_id:
                self.source_list.select_row(row)
        self.empty.set_visible(not inventory)

    def import_sources(self, _):
        buffer = self.input.get_buffer()
        raw = buffer.get_text(*buffer.get_bounds(), True)
        hwid = self.import_hwid.get_text().strip()
        if not raw.strip():
            self.source_notice.set_text(tr("Вставьте ссылку или конфиг."))
            self.input.grab_focus()
            return

        def completed(result):
            lines = raw.split("\n")
            retry, details = [], []
            for issue in result.get("Issues") or ():
                number = issue["Line"]
                if 1 <= number <= len(lines):
                    retry.append(lines[number - 1])
                    reason = ISSUE_TEXT.get(issue["Reason"]) or tr("проверьте формат источника")
                    details.append(tr("Строка {0} — {1}", len(retry), reason))
            buffer.set_text("\n".join(retry))
            if not retry:
                self.import_hwid.set_text("")
            self.source_notice.set_text("\n".join((self.import_summary(result), *details)))

        if hwid and not re.fullmatch(r"[A-Za-z0-9=-]{10,64}", hwid):
            self.source_notice.set_text(tr("В HWID должно быть 10–64 символа: латиница, цифры, дефис или знак равенства."))
            self.import_hwid.grab_focus()
            return
        self.action("POST", "/sources/import", raw, self.source_notice, tr("Импортируем источники…"), completed,
                    headers={"X-Hydrat-Source-HWID": hwid} if hwid else None)

    @staticmethod
    def import_summary(result):
        counts = [f"{name}: {result[key]}" for key, name in
                  (("Imported", tr("Добавлено")), ("Restored", tr("Восстановлено")), ("Skipped", tr("Уже в списке")),
                   ("Unavailable", tr("Некорректных строк")), ("RefreshFailed", tr("Ошибок загрузки"))) if result.get(key)]
        return " · ".join(counts) or tr("Нет источников для импорта.")

    def import_suggested(self, _):
        self.action("POST", "/sources/suggested", None, self.source_notice, tr("Проверяем подписки…"),
                    lambda result: self.source_notice.set_text(self.import_summary(result)))

    def refresh_sources(self, _):
        self.action("POST", "/sources/refresh", None, self.source_notice, tr("Обновляем источники…"),
                    lambda result: self.source_notice.set_text(tr("Обновлено: {0} · Ошибок: {1}", result['Updated'], result['Failed'])))

    def edit_source_hwid(self, _):
        row = self.source_list.get_selected_row()
        if row is None or row.source["Kind"] not in SUBSCRIPTION_KINDS:
            return
        source = row.source
        path = "/sources/" + quote(source["ID"], safe="") + "/hwid"

        def loaded(result):
            self.source_notice.set_text("")
            dialog = css(Gtk.Dialog(title=tr("HWID источника"), transient_for=self, modal=True, destroy_with_parent=True), "hydrat")
            dialog.add_buttons(tr("Отмена"), Gtk.ResponseType.CANCEL, tr("Сохранить"), Gtk.ResponseType.OK)
            dialog.set_default_response(Gtk.ResponseType.OK)
            content = dialog.get_content_area()
            content.set_border_width(16)
            content.set_spacing(8)
            add(content, label(source["Label"] or tr("Подписка"), "section"))
            entry = add(content, Gtk.Entry(text=result["HWID"], max_length=64, placeholder_text=tr("Общий HWID")))
            entry.set_activates_default(True)
            entry.get_accessible().set_name(tr("HWID источника"))
            add(content, label(tr("Пустое поле использует общий HWID."), "muted"))
            content.show_all()
            response = dialog.run()
            value = entry.get_text().strip()
            dialog.destroy()
            if response == Gtk.ResponseType.OK:
                self.action("PUT", path, {"HWID": value}, self.source_notice, tr("Сохраняем HWID…"),
                            lambda report: self.source_notice.set_text(tr("HWID сохранён. Не удалось обновить источник.")
                                                                     if report["Failed"] else tr("HWID сохранён. Источник обновлён.")))

        self.action("GET", path, None, self.source_notice, tr("Загружаем HWID…"), loaded)

    def delete_source(self, _):
        row = self.source_list.get_selected_row()
        if row is None:
            return
        source = row.source
        name = source["Label"] or tr("выбранный источник")
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION,
                                   buttons=Gtk.ButtonsType.OK_CANCEL, text=tr("Удалить «{0}» и его ноды?", name))
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        response = dialog.run()
        dialog.destroy()
        if response == Gtk.ResponseType.OK:
            self.action("DELETE", "/sources/" + quote(source["ID"], safe=""), None, self.source_notice, tr("Удаляем источник…"),
                        lambda _: self.source_notice.set_text(tr("Источник удалён.")))

    def settings(self):
        outer = box(gap=6)
        tabs = Gtk.Stack()
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(tabs)
        add(outer, switcher)
        add(outer, tabs, True)
        tabs.add_titled(self.connection_settings(), "common", tr("Общие"))
        tabs.add_titled(self.geo_settings(), "geo", "GeoIP / GeoSite")
        tabs.add_titled(scrolled(self.update_settings()), "updates", tr("Обновления"))
        tabs.add_titled(self.language_settings(), "language", tr("Язык"))
        return outer

    def language_settings(self):
        page = box()
        card = add(page, panel(tr("Язык")))
        choice = Gtk.ComboBoxText()
        for value, title in zip(LANGUAGE_CHOICES, (tr("Автоматически"), "Русский", "English", "简体中文")):
            choice.append(value or "auto", title)
        choice.set_active_id(saved_language() or "auto")
        add(card, choice)
        notice = add(card, label(style="muted"))

        def save(_):
            value = choice.get_active_id()
            if value is None:
                return
            try:
                save_language("" if value == "auto" else value)
                notice.set_text(tr("Язык изменится при следующем запуске Hydrat."))
            except OSError:
                notice.set_text(tr("Не удалось сохранить язык."))

        add(card, button(tr("Сохранить"), save, "primary"))
        return page

    def update_settings(self):
        page = box()
        card = add(page, panel(tr("Обновления")))
        try:
            version = (APP_DIR / "VERSION").read_text().strip()
        except OSError:
            version = ""
        self.installed_version = add(card, label(tr("Установлена версия {0}", version) if version else tr("Установленная версия"), "muted"))
        self.check_update_button = add(card, button(tr("Проверить обновления"), self.check_update))
        self.check_update_button.set_halign(Gtk.Align.START)
        self.update_notice = add(card, label(style="muted"))
        self.download_update = add(card, Gtk.LinkButton(label=tr("Скачать DEB")))
        self.download_update.set_halign(Gtk.Align.START)
        self.download_update.set_no_show_all(True)
        return page

    def check_update(self, _):
        self.check_update_button.set_sensitive(False)
        self.download_update.hide()
        self.update_notice.set_text(tr("Проверяем обновления…"))

        def checked(result, error):
            self.check_update_button.set_sensitive(True)
            if error:
                self.update_notice.set_text(error)
                return
            self.installed_version.set_text(tr("Установлена версия {0}", result['Current']))
            if result["DownloadURL"]:
                self.update_notice.set_text(tr("Доступна версия {0}", result['Latest']))
                self.download_update.set_uri(result["DownloadURL"])
                self.download_update.show()
            else:
                self.update_notice.set_text(tr("Установлена актуальная версия.") if result["Latest"] else tr("Подходящих релизов пока нет."))

        self.request("GET", "/updates", complete=checked, timeout=16)

    def connection_settings(self):
        page, fields = box(), box()
        self.fields = {}
        conn = add(fields, panel(tr("Подключение")))
        self.dns = Gtk.ComboBoxText()
        for name in (tr("Авто"), "Cloudflare", "Quad9", "Google"):
            self.dns.append_text(name)
        self.dns.set_active(0)
        add_field(conn, tr("DNS-резолвер"), self.dns)
        self.geo_rules = add(conn, Gtk.CheckButton(label=tr("Правила GeoIP и GeoSite")))
        search = add(fields, panel(tr("Поиск и качество")))
        for key, name, low, high in (
            ("FastWorkers", tr("Проверок при подключении"), 1, 8),
            ("BackgroundWorkers", tr("Проверок в фоне"), 1, 8),
            ("MinVLESSScore", tr("Порог качества VLESS"), 50, 100),
            ("BackgroundIntervalSeconds", tr("Интервал поиска, с"), 15, 900),
        ):
            widget = Gtk.SpinButton.new_with_range(low, high, 1)
            self.fields[key] = widget
            add_field(search, name, widget)
        sources = add(fields, panel(tr("Подписки")))
        interval = Gtk.SpinButton.new_with_range(15, 1440, 1)
        self.fields["SourceRefreshMinutes"] = interval
        add_field(sources, tr("Обновлять каждые, мин"), interval)
        self.hwid = Gtk.Entry(max_length=64, placeholder_text=tr("Автоматически"))
        add_field(sources, tr("HWID для VLESS"), self.hwid)
        add(sources, label(tr("10–64 символа. Латиница, цифры, дефис и знак равенства."), "muted"))
        add(page, scrolled(fields), True)
        add(page, label(tr("Настройки подключения применяются при следующем подключении."), "muted"))
        self.settings_notice = add(page, label(style="muted"))
        self.save = add(page, button(tr("Сохранить"), self.save_settings, "primary"))
        self.save.set_halign(Gtk.Align.END)
        return page

    def geo_settings(self):
        page, fields = box(), box()
        self.geofields = {}
        for group, specs in (
            (tr("Базы"), (("IPURL", tr("Ссылка на GeoIP")), ("SiteURL", tr("Ссылка на GeoSite")))),
            (tr("Правила маршрутизации"), (("TunnelIP", tr("GeoIP через VPN")), ("DirectIP", tr("GeoIP напрямую")),
                                      ("TunnelSite", tr("GeoSite через VPN")), ("DirectSite", tr("GeoSite напрямую")))),
        ):
            card = add(fields, panel(group))
            if group == tr("Базы"):
                add(card, label(tr("Укажите HTTPS-ссылки на .dat. Пустые поля используют встроенные базы."), "muted"))
            for key, name in specs:
                widget = Gtk.Entry(max_length=4096)
                self.geofields[key] = widget
                add_field(card, name, widget)
        add(page, scrolled(fields), True)
        add(page, label(tr("Правила применяются при следующем подключении."), "muted"))
        self.geo_notice = add(page, label(style="muted"))
        self.save_geo = add(page, button(tr("Проверить и сохранить"), self.save_geo_rules, "primary"))
        self.save_geo.set_halign(Gtk.Align.END)
        return page

    def page_changed(self, *_):
        if self.pages.get_visible_child_name() != "settings":
            return

        def connected(result, error):
            if error:
                self.settings_notice.set_text(error)
                return
            self.dns.set_active(result["DNSPreset"])
            self.geo_rules.set_active(result["GeoRules"])
            self.hwid.set_text(result["HWID"])
            for key, widget in self.fields.items():
                widget.set_value(result[key])
            self.prefs_loaded = True
            self.render_actions()

        def geo_loaded(result, error):
            if error:
                self.geo_notice.set_text(error)
                return
            for key, widget in self.geofields.items():
                widget.set_text(result[key])
            self.geo_loaded = True
            self.render_actions()

        if not self.prefs_loaded:
            self.request("GET", "/settings", complete=connected, timeout=5)
        if not self.geo_loaded:
            self.request("GET", "/settings/geo", complete=geo_loaded, timeout=5)

    def save_settings(self, _):
        values = {key: widget.get_value_as_int() for key, widget in self.fields.items()}
        values.update(DNSPreset=self.dns.get_active(), GeoRules=self.geo_rules.get_active(),
                      HWID=self.hwid.get_text().strip())
        self.action("PUT", "/settings", values, self.settings_notice, tr("Сохраняем…"),
                    lambda _: self.settings_notice.set_text(tr("Настройки сохранены.")))

    def save_geo_rules(self, _):
        values = {key: widget.get_text().strip() for key, widget in self.geofields.items()}
        self.action("PUT", "/settings/geo", values, self.geo_notice, tr("Проверяем правила…"),
                    lambda _: self.geo_notice.set_text(tr("Правила сохранены.")))


def add_field(parent, title, widget):
    row = add(parent, box(horizontal=True, gap=12))
    field_label = add(row, label(title, "muted"))
    field_label.set_size_request(155, -1)
    field_label.set_mnemonic_widget(widget)
    add(row, widget, not isinstance(widget, Gtk.SpinButton))


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--socket", default=SOCKET)
    api = LocalAPI(args.parse_args().socket)
    application = Gtk.Application(application_id="org.hydrat.App")

    def activate(app):
        window = app.get_active_window()
        if window is None:
            provider = Gtk.CssProvider()
            provider.load_from_path(str(APP_DIR / "theme.css"))
            Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider,
                                                     Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            window = Window(app, api)
        window.present()

    application.connect("activate", activate)
    return application.run([])


if __name__ == "__main__":
    raise SystemExit(main())

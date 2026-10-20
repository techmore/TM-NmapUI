/* Scanner summary for Pantheon's Wingpanel: scan state, hosts and alerts, with an Open button.
 * Reads one JSON object from ~/.local/bin/nmapui-summary (loopback scanner API only). */
using GLib;
using Gtk;
using Json;
using Wingpanel;

namespace MSeries {
    public class NmapUIIndicator : Wingpanel.Indicator {
        private const string ICON = "mseries-nmapui-radar-symbolic";
        private const uint POLL_SECONDS = 10;

        private Gtk.Box panel;
        private Gtk.Label panel_value;
        private Gtk.Label panel_dot;
        private Gtk.Box menu;
        private Gtk.Label state_title;
        private Gtk.Label state_detail;
        private Gtk.ProgressBar progress;
        private Gtk.Label scan_target_label;
        private Gtk.Label scan_step_label;
        private Gtk.Label scan_time_label;
        private Gtk.Label net_link_label;
        private Gtk.Label net_addr_label;
        private Gtk.Label net_gw_label;
        private Gtk.Label devices_title;
        private Gtk.ListBox device_list;
        private Gtk.ScrolledWindow device_scroll;
        private string last_devices_key = "";
        private Gtk.Label hosts_value;
        private Gtk.Label changes_value;
        private Gtk.Label critical_value;
        private Gtk.Box alert_box;
        private Gtk.Label last_scan_label;
        private Gtk.Label monitor_label;
        private Gtk.Button open_button;
        private string helper;
        private bool in_flight = false;
        private uint poll_source = 0;
        private string last_json = "";

        public NmapUIIndicator () {
            GLib.Object (code_name: "nmapui");
        }

        construct {
            helper = GLib.Path.build_filename (Environment.get_home_dir (), ".local", "bin", "nmapui-summary");

            panel = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 4);
            panel.add_css_class ("mseries-nmapui-bar");
            panel.append (new Gtk.Image.from_icon_name (ICON) { pixel_size = 16, valign = Gtk.Align.CENTER });
            panel_value = new Gtk.Label ("") { valign = Gtk.Align.CENTER, visible = false };
            panel_value.add_css_class ("seg-value");
            panel.append (panel_value);
            panel_dot = new Gtk.Label ("●") { valign = Gtk.Align.CENTER, visible = false };
            panel.append (panel_dot);
            panel.set_tooltip_text ("Network Scanner · loading…");
            this.visible = true;

            menu = new Gtk.Box (Gtk.Orientation.VERTICAL, 8) {
                margin_top = 8, margin_bottom = 8, margin_start = 8, margin_end = 8, width_request = 320
            };
            menu.add_css_class ("mseries-nmapui");
            install_style (menu.get_display ());

            // Status card: state, current activity and scan progress.
            var card = new Gtk.Box (Gtk.Orientation.VERTICAL, 4);
            card.add_css_class ("card");
            state_title = new Gtk.Label ("Loading…") { xalign = 0 };
            state_title.add_css_class ("state-title");
            state_detail = new Gtk.Label ("") { xalign = 0, wrap = true, visible = false };
            state_detail.add_css_class ("caption");
            state_detail.add_css_class ("dim-label");
            progress = new Gtk.ProgressBar () { visible = false };
            card.append (state_title);
            card.append (state_detail);
            card.append (progress);
            scan_target_label = new Gtk.Label ("") { xalign = 0, visible = false };
            scan_step_label = new Gtk.Label ("") { xalign = 0, visible = false };
            scan_time_label = new Gtk.Label ("") { xalign = 0, visible = false };
            foreach (var l in new Gtk.Label[] { scan_target_label, scan_step_label, scan_time_label }) {
                l.add_css_class ("caption");
                l.add_css_class ("numeric");
                card.append (l);
            }
            menu.append (card);

            // Network card: where this machine sits, from the kernel (no internet lookups).
            var net = new Gtk.Box (Gtk.Orientation.VERTICAL, 2);
            net.add_css_class ("card");
            var net_title = new Gtk.Label ("Network") { xalign = 0 };
            net_title.add_css_class ("state-title");
            net_link_label = new Gtk.Label ("") { xalign = 0 };
            net_addr_label = new Gtk.Label ("") { xalign = 0 };
            net_gw_label = new Gtk.Label ("") { xalign = 0 };
            net.append (net_title);
            foreach (var l in new Gtk.Label[] { net_link_label, net_addr_label, net_gw_label }) {
                l.add_css_class ("caption");
                l.add_css_class ("numeric");
                net.append (l);
            }
            menu.append (net);

            // Three headline numbers.
            var metrics = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 6) { homogeneous = true };
            metrics.append (metric ("Hosts", out hosts_value));
            metrics.append (metric ("Changes", out changes_value));
            metrics.append (metric ("Critical", out critical_value));
            menu.append (metrics);

            alert_box = new Gtk.Box (Gtk.Orientation.VERTICAL, 4);
            menu.append (alert_box);

            // Devices from the latest scan: name or vendor, address and open-port count.
            devices_title = new Gtk.Label ("Devices") { xalign = 0, visible = false };
            devices_title.add_css_class ("state-title");
            device_list = new Gtk.ListBox () { selection_mode = Gtk.SelectionMode.NONE };
            device_list.add_css_class ("device-list");
            device_scroll = new Gtk.ScrolledWindow () { child = device_list, min_content_height = 60, max_content_height = 200,
                                                        propagate_natural_height = true, hscrollbar_policy = Gtk.PolicyType.NEVER, visible = false };
            menu.append (devices_title);
            menu.append (device_scroll);

            last_scan_label = new Gtk.Label ("") { xalign = 0, wrap = true };
            last_scan_label.add_css_class ("caption");
            last_scan_label.add_css_class ("dim-label");
            monitor_label = new Gtk.Label ("") { xalign = 0, visible = false };
            monitor_label.add_css_class ("caption");
            monitor_label.add_css_class ("dim-label");
            menu.append (last_scan_label);
            menu.append (monitor_label);

            // Footer dock: the one action that matters.
            var dock = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 6);
            dock.add_css_class ("mseries-dock");
            open_button = new Gtk.Button.with_label ("Open Network Scanner") { hexpand = true };
            open_button.add_css_class ("suggested-action");
            open_button.clicked.connect (open_app);
            var refresh_button = new Gtk.Button.from_icon_name ("view-refresh-symbolic") { tooltip_text = "Refresh" };
            refresh_button.add_css_class ("flat");
            refresh_button.clicked.connect (() => refresh ());
            dock.append (open_button);
            dock.append (refresh_button);
            menu.append (dock);

            refresh ();
            poll_source = Timeout.add_seconds (POLL_SECONDS, () => { refresh (); return Source.CONTINUE; });
        }

        ~NmapUIIndicator () {
            if (poll_source != 0) Source.remove (poll_source);
        }

        private Gtk.Widget metric (string title, out Gtk.Label value) {
            var box = new Gtk.Box (Gtk.Orientation.VERTICAL, 0);
            box.add_css_class ("metric");
            value = new Gtk.Label ("–");
            value.add_css_class ("metric-value");
            var caption = new Gtk.Label (title);
            caption.add_css_class ("caption");
            caption.add_css_class ("dim-label");
            box.append (value);
            box.append (caption);
            return box;
        }

        private static void install_style (Gdk.Display display) {
            var style = new Gtk.CssProvider ();
            style.load_from_string (
                ".mseries-nmapui { font-size: 9pt; } " +
                ".mseries-nmapui .caption { font-size: 8pt; } " +
                ".mseries-nmapui .card { padding: 8px 10px; border-radius: 8px; background: alpha(currentColor, 0.06); } " +
                ".mseries-nmapui .state-title { font-weight: 700; font-size: 10pt; } " +
                ".mseries-nmapui .metric { padding: 6px 4px; border-radius: 8px; background: alpha(currentColor, 0.06); } " +
                ".mseries-nmapui .metric-value { font-weight: 700; font-size: 14pt; font-feature-settings: \"tnum\"; } " +
                ".mseries-nmapui .alert-row { padding: 5px 8px; border-radius: 8px; background: alpha(@warning_color, 0.18); } " +
                ".mseries-nmapui .alert-row.bad { background: alpha(@error_color, 0.18); } " +
                ".mseries-nmapui .device-list { background: transparent; } " +
                ".mseries-nmapui .device-row { padding: 4px 8px; border-radius: 8px; background: alpha(currentColor, 0.05); margin: 1px 0; } " +
                ".mseries-nmapui .device-name { font-weight: 600; } " +
                ".mseries-nmapui .chip { padding: 0 7px; border-radius: 99px; font-size: 7.5pt; font-weight: 700; background: alpha(@accent_color, 0.2); color: @accent_color; } " +
                ".mseries-nmapui .mseries-dock { margin-top: 2px; } " +
                ".mseries-nmapui-bar .seg-value { font-size: 7pt; font-weight: 700; } " +
                ".mseries-nmapui-bar .dot-scan { color: @accent_color; font-size: 7pt; } " +
                ".mseries-nmapui-bar .dot-warn { color: @warning_color; font-size: 7pt; } " +
                ".mseries-nmapui-bar .dot-off { opacity: 0.45; font-size: 7pt; } ");
            Gtk.StyleContext.add_provider_for_display (display, style, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION);
        }

        private void update_devices (Json.Object data) {
            Json.Array? devices = data.has_member ("devices") && !data.get_null_member ("devices") ? data.get_array_member ("devices") : null;
            uint count = devices != null ? devices.get_length () : 0;
            devices_title.visible = device_scroll.visible = count > 0;
            devices_title.label = "Devices · %u".printf (count);
            var key = new StringBuilder ();
            for (uint i = 0; i < count; i++) {
                var d = devices.get_object_element (i);
                key.append (d.get_string_member_with_default ("ip", "")).append (d.get_string_member_with_default ("name", ""));
                key.append (d.has_member ("open_ports") && !d.get_null_member ("open_ports") ? d.get_int_member ("open_ports").to_string () : "-");
            }
            if (key.str == last_devices_key) return;
            last_devices_key = key.str;
            Gtk.Widget? child;
            while ((child = device_list.get_first_child ()) != null) device_list.remove (child);
            for (uint i = 0; i < count; i++) {
                var d = devices.get_object_element (i);
                string name = d.get_string_member_with_default ("name", "");
                string vendor = d.get_string_member_with_default ("vendor", "");
                if (name == "") name = vendor.has_prefix ("(") ? "Unknown device" : (vendor != "" ? vendor : "Unknown device");
                var row = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 8);
                row.add_css_class ("device-row");
                var text = new Gtk.Box (Gtk.Orientation.VERTICAL, 0) { hexpand = true };
                var title = new Gtk.Label (name) { xalign = 0, ellipsize = Pango.EllipsizeMode.END };
                title.add_css_class ("device-name");
                var sub = new Gtk.Label (d.get_string_member_with_default ("ip", "") + (vendor != "" && vendor != name ? " · " + vendor : "")) { xalign = 0, ellipsize = Pango.EllipsizeMode.END };
                sub.add_css_class ("caption");
                sub.add_css_class ("dim-label");
                sub.add_css_class ("numeric");
                text.append (title);
                text.append (sub);
                row.append (text);
                if (d.has_member ("open_ports") && !d.get_null_member ("open_ports")) {
                    var chip = new Gtk.Label ("%lld open".printf (d.get_int_member ("open_ports"))) { valign = Gtk.Align.CENTER };
                    chip.add_css_class ("chip");
                    row.append (chip);
                }
                device_list.append (row);
            }
        }

        private void open_app () {
            try {
                var info = new DesktopAppInfo ("io.github.techmore.NmapUI.desktop");
                if (info != null) {
                    info.launch (null, null);
                } else {
                    Process.spawn_command_line_async ("nmapui-elementary");
                }
            } catch (Error e) {
                warning ("Could not open Network Scanner: %s", e.message);
            }
            close ();
        }

        private void refresh () {
            if (in_flight) return;
            in_flight = true;
            try {
                var process = new Subprocess (SubprocessFlags.STDOUT_PIPE | SubprocessFlags.STDERR_SILENCE, helper);
                process.communicate_utf8_async.begin (null, null, (obj, res) => {
                    in_flight = false;
                    try {
                        string? out_text;
                        process.communicate_utf8_async.end (res, out out_text, null);
                        apply (out_text ?? "");
                    } catch (Error e) {
                        apply ("");
                    }
                });
            } catch (Error e) {
                in_flight = false;
                apply ("");
            }
        }

        private static string relative (string iso) {
            var then = new DateTime.from_iso8601 (iso, null);
            if (then == null) return iso;
            var seconds = new DateTime.now_utc ().difference (then) / TimeSpan.SECOND;
            if (seconds < 90) return "just now";
            if (seconds < 5400) return "%d min ago".printf ((int) (seconds / 60));
            if (seconds < 129600) return "%d h ago".printf ((int) (seconds / 3600));
            return "%d days ago".printf ((int) (seconds / 86400));
        }

        private static string number_or_dash (Json.Object o, string key) {
            return o.has_member (key) && !o.get_null_member (key) ? o.get_int_member (key).to_string () : "–";
        }

        private void apply (string text) {
            if (text == last_json && text != "") return;
            last_json = text;
            Json.Object? data = null;
            try {
                var parser = new Json.Parser ();
                parser.load_from_data (text);
                var root = parser.get_root ();
                if (root != null && root.get_node_type () == Json.NodeType.OBJECT) data = root.get_object ();
            } catch (Error e) {}

            panel_dot.remove_css_class ("dot-scan");
            panel_dot.remove_css_class ("dot-warn");
            panel_dot.remove_css_class ("dot-off");
            if (data == null) {
                state_title.label = "Summary unavailable";
                state_detail.visible = false;
                progress.visible = false;
                panel_value.visible = false;
                panel_dot.visible = true;
                panel_dot.add_css_class ("dot-off");
                panel.set_tooltip_text ("Network Scanner · summary unavailable");
                return;
            }

            string state = data.get_string_member_with_default ("state", "offline");
            string label = data.get_string_member_with_default ("label", "Unknown");
            state_title.label = label;
            string? message = data.has_member ("message") && !data.get_null_member ("message") ? data.get_string_member ("message") : null;
            state_detail.visible = message != null && message != "";
            state_detail.label = message ?? "";
            bool scanning = state == "scanning" || state == "stopping";
            progress.visible = scanning && data.has_member ("progress") && !data.get_null_member ("progress");
            if (progress.visible) progress.fraction = (double) data.get_int_member ("progress") / 100.0;

            // Ongoing scan details.
            scan_target_label.visible = scan_step_label.visible = scan_time_label.visible = false;
            if (scanning && data.has_member ("scan") && !data.get_null_member ("scan")) {
                var scan = data.get_object_member ("scan");
                string target = scan.has_member ("target") && !scan.get_null_member ("target") ? scan.get_string_member ("target") : "";
                scan_target_label.visible = target != "";
                scan_target_label.label = "Target %s".printf (target);
                if (scan.has_member ("index") && !scan.get_null_member ("index") && scan.has_member ("total") && !scan.get_null_member ("total")) {
                    string current = scan.has_member ("current") && !scan.get_null_member ("current") ? " · " + scan.get_string_member ("current") : "";
                    scan_step_label.visible = true;
                    scan_step_label.label = "Host %lld of %lld%s".printf (scan.get_int_member ("index"), scan.get_int_member ("total"), current);
                }
                if (scan.has_member ("elapsed_seconds") && !scan.get_null_member ("elapsed_seconds")) {
                    int64 sec = scan.get_int_member ("elapsed_seconds");
                    scan_time_label.visible = true;
                    scan_time_label.label = sec >= 3600 ? "Running %lldh %lldm".printf (sec / 3600, (sec % 3600) / 60) : "Running %lldm %llds".printf (sec / 60, sec % 60);
                }
            }

            // Network facts.
            net_link_label.label = "Link unknown";
            net_addr_label.label = "";
            net_gw_label.label = "";
            if (data.has_member ("network") && !data.get_null_member ("network")) {
                var net = data.get_object_member ("network");
                string iface = net.has_member ("interface") && !net.get_null_member ("interface") ? net.get_string_member ("interface") : "";
                string ssid = net.has_member ("ssid") && !net.get_null_member ("ssid") ? net.get_string_member ("ssid") : "";
                string addr = net.has_member ("address") && !net.get_null_member ("address") ? net.get_string_member ("address") : "";
                string cidr = net.has_member ("cidr") && !net.get_null_member ("cidr") ? net.get_string_member ("cidr") : "";
                string gw = net.has_member ("gateway") && !net.get_null_member ("gateway") ? net.get_string_member ("gateway") : "";
                net_link_label.label = iface == "" ? "Offline" : (ssid != "" ? "%s · %s".printf (ssid, iface) : iface);
                net_addr_label.label = addr == "" ? "" : "Address %s%s".printf (addr, cidr != "" ? " (" + cidr + ")" : "");
                net_gw_label.label = gw == "" ? "" : "Gateway %s".printf (gw);
            }
            net_addr_label.visible = net_addr_label.label != "";
            net_gw_label.visible = net_gw_label.label != "";

            update_devices (data);

            hosts_value.label = number_or_dash (data, "hosts");
            changes_value.label = number_or_dash (data, "changes");
            critical_value.label = number_or_dash (data, "critical");

            // Panel: host count when known, plus one state dot.
            bool hosts_known = data.has_member ("hosts") && !data.get_null_member ("hosts");
            panel_value.visible = hosts_known;
            if (hosts_known) panel_value.label = data.get_int_member ("hosts").to_string ();
            panel_dot.visible = state != "idle";
            if (state == "scanning" || state == "stopping") panel_dot.add_css_class ("dot-scan");
            else if (state == "attention") panel_dot.add_css_class ("dot-warn");
            else if (state == "offline") panel_dot.add_css_class ("dot-off");

            Gtk.Widget? child;
            while ((child = alert_box.get_first_child ()) != null) alert_box.remove (child);
            if (data.has_member ("alerts")) {
                var alerts = data.get_array_member ("alerts");
                for (uint i = 0; i < alerts.get_length (); i++) {
                    var row = new Gtk.Label (alerts.get_string_element (i)) { xalign = 0, wrap = true };
                    row.add_css_class ("alert-row");
                    if (alerts.get_string_element (i).contains ("critical")) row.add_css_class ("bad");
                    alert_box.append (row);
                }
            }

            string last = data.has_member ("last_scan") && !data.get_null_member ("last_scan") ? data.get_string_member ("last_scan") : "";
            string customer = data.has_member ("last_customer") && !data.get_null_member ("last_customer") ? data.get_string_member ("last_customer") : "";
            last_scan_label.visible = !scanning;
            last_scan_label.label = last == "" ? "No saved scans yet" : "Last scan %s%s".printf (relative (last), customer != "" ? " · " + customer : "");
            monitor_label.visible = data.has_member ("monitor") && !data.get_null_member ("monitor");
            if (monitor_label.visible) monitor_label.label = "Auto-monitor: " + data.get_string_member ("monitor");

            panel.set_tooltip_text ("Network Scanner · " + label + (hosts_known ? " · %s hosts".printf (hosts_value.label) : ""));
        }

        public override Gtk.Widget get_display_widget () {
            return panel;
        }

        public override Gtk.Widget? get_widget () {
            return menu;
        }

        public override void opened () {
            refresh ();
        }

        public override void closed () {
        }
    }
}

public Wingpanel.Indicator? get_indicator (Module module, Wingpanel.ServerType server_type) {
    if (server_type != Wingpanel.ServerType.SESSION) return null;
    return new MSeries.NmapUIIndicator ();
}

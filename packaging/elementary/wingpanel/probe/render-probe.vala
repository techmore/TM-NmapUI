/* Headless render probe: loads the real NmapUI indicator and writes the panel item + popover to a PNG.
 * Usage: render-probe OUT.png [delay-ms]   (run under Xvfb with a fake HOME; see run-probe.sh) */
bool render_failed = false;

int main (string[] args) {
    if (args.length < 2) {
        stderr.printf ("usage: render-probe OUT.png [delay-ms]\n");
        return 2;
    }
    Gtk.init ();
    Granite.init ();
    var delay = args.length > 2 ? int.parse (args[2]) : 1500;
    var icons = Environment.get_variable ("NMAPUI_ICONS");
    if (icons != null) Gtk.IconTheme.get_for_display (Gdk.Display.get_default ()).add_search_path (icons);
    var indicator = new MSeries.NmapUIIndicator ();
    var bar = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 0) { height_request = 28, margin_start = 8, margin_end = 8 };
    bar.append (indicator.get_display_widget ());
    var popover_body = new Gtk.Box (Gtk.Orientation.VERTICAL, 0);
    popover_body.add_css_class ("background");
    popover_body.append (indicator.get_widget ());
    var root = new Gtk.Box (Gtk.Orientation.VERTICAL, 6) { margin_top = 6, margin_bottom = 6, margin_start = 6, margin_end = 6 };
    root.add_css_class ("background");
    root.append (bar);
    root.append (popover_body);
    var window = new Gtk.Window () { child = root, decorated = false };
    window.present ();

    var loop = new MainLoop ();
    Timeout.add (delay, () => {
        int min, nat;
        root.measure (Gtk.Orientation.VERTICAL, 400, out min, out nat, null, null);
        window.set_default_size (400, nat);
        Timeout.add (900, () => {
            var paintable = new Gtk.WidgetPaintable (root);
            var snapshot = new Gtk.Snapshot ();
            paintable.snapshot (snapshot, root.get_width (), root.get_height ());
            var node = snapshot.to_node ();
            var renderer = window.get_native ().get_renderer ();
            if (node == null || renderer == null) {
                stderr.printf ("nothing to render\n");
                render_failed = true;
            } else {
                renderer.render_texture (node, null).save_to_png (args[1]);
            }
            loop.quit ();
            return Source.REMOVE;
        });
        return Source.REMOVE;
    });
    loop.run ();
    return render_failed ? 1 : 0;
}

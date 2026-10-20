project('mseries-nmapui-wingpanel', 'vala', version: '0.1.0', meson_version: '>= 0.59.0')

libwingpanel_dep = dependency('wingpanel-9')
granite_dep = dependency('granite-7', version: '>= 7.7.0')
json_dep = dependency('json-glib-1.0')
indicators_dir = libwingpanel_dep.get_variable(pkgconfig: 'indicatorsdir')
icon_theme_dir = join_paths(get_option('datadir'), 'icons', 'hicolor', 'symbolic', 'apps')

shared_module(
  'nmapui',
  'Indicator.vala',
  dependencies: [libwingpanel_dep, granite_dep, json_dep],
  install: true,
  install_dir: indicators_dir,
)

install_data('icons/mseries-nmapui-radar-symbolic.svg', install_dir: icon_theme_dir)

# Headless render probe (not installed): see probe/run-probe.sh.
executable(
  'render-probe',
  'Indicator.vala', 'probe/render-probe.vala',
  dependencies: [libwingpanel_dep, granite_dep, json_dep],
  install: false,
)

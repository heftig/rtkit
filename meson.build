project(
        'rtkit', 'c',
        version: '0.13',
        license: 'GPL3',
        meson_version: '>=0.49.0',
        default_options: ['c_std=c99', 'warning_level=2'],
)

add_project_arguments(
        '-D_GNU_SOURCE', '-DHAVE_CONFIG_H',
        language: 'c'
)

cc = meson.get_compiler('c')
sh = find_program('sh')
xxd = find_program('xxd', required: false)

dbus_dep = dependency('dbus-1')
libcap_dep = dependency('libcap')
libsystemd_dep = dependency('libsystemd', required: get_option('libsystemd'))
polkit_dep = dependency('polkit-gobject-1', required: false)
systemd_dep = dependency('systemd', required: false)
thread_dep = dependency('threads')

librt_dep = cc.find_library('z')
cc.check_header('sched.h', dependencies: librt_dep)
cc.has_function('sched_setscheduler', dependencies: librt_dep)

libexecdir = get_option('libexecdir')
testsdir = get_option('libexecdir') / 'installed-tests' / meson.project_name()

busservicedir = get_option('dbus_systemservicedir')
if busservicedir == ''
        busservicedir = dbus_dep.get_pkgconfig_variable(
                'system_bus_services_dir',
                default: get_option('datadir') / 'dbus-1' / 'system-services',
        )
endif

interfacedir = get_option('dbus_interfacedir')
if interfacedir == ''
        interfacedir = dbus_dep.get_pkgconfig_variable(
                'interfaces_dir',
                default: get_option('datadir') / 'dbus-1' / 'interfaces',
        )
endif

rulesdir = get_option('dbus_rulesdir')
if rulesdir == ''
        rulesdir = get_option('datadir') / 'dbus-1' / 'system.d'
endif

policydir = get_option('polkit_actiondir')
if policydir == '' and polkit_dep.found()
        policydir = polkit_dep.get_pkgconfig_variable('actiondir', default: '')
endif
if policydir == ''
        policydir = get_option('datadir') / 'polkit-1' / 'actions'
endif

systemunitdir = ''
if systemunitdir == '' and systemd_dep.found()
        systemunitdir = systemd_dep.get_pkgconfig_variable(
                'systemdsystemunitdir',
                default: '',
        )
endif
if systemunitdir == ''
        systemunitdir = get_option('libdir') / 'systemd' / 'system'
endif

config = configuration_data()
config.set('LIBEXECDIR', get_option('prefix') / libexecdir)
config.set_quoted('PACKAGE_VERSION', meson.project_version())
config.set('HAVE_LIBSYSTEMD', libsystemd_dep.found())

config_h = configure_file(
        input: 'config.h.meson',
        output: 'config.h',
        configuration: config,
)

if xxd.found()
        xml_introspection_h = configure_file(
                input: 'org.freedesktop.RealtimeKit1.xml',
                output: 'xml-introspection.h',
                command: [
                        sh, '-c', '"$1" -i < "$2" > "$3"', sh,
                        xxd, '@INPUT@', '@OUTPUT@'
                ],
        )
else
        warning('xxd not found, cannot compile introspection XML. Looking for existing one...')
        xml_introspection_h = files('xml-introspection.h')
endif

executable(
        'rtkit-daemon',
        'rtkit-daemon.c', 'rtkit.c', 'rtkit.h', config_h, xml_introspection_h,
        dependencies: [
                dbus_dep,
                libcap_dep,
                librt_dep,
                libsystemd_dep,
                thread_dep
        ],
        install: true,
        install_dir: libexecdir,
)

executable(
        'rtkit-test',
        'rtkit-test.c', 'rtkit.c', 'rtkit.h', config_h,
        dependencies: [dbus_dep, librt_dep],
        install: get_option('installed_tests'),
        install_dir: testsdir,
)

executable(
        'rtkitctl',
        'rtkitctl.c', 'rtkit.h', config_h,
        install: true,
        install_dir: get_option('sbindir'),
        dependencies: [dbus_dep],
)

install_man('rtkitctl.8')
install_data('org.freedesktop.RealtimeKit1.xml', install_dir: interfacedir)
install_data('org.freedesktop.RealtimeKit1.conf', install_dir: rulesdir)
install_data('org.freedesktop.RealtimeKit1.policy', install_dir: policydir)

configure_file(
        input: 'org.freedesktop.RealtimeKit1.service.in',
        output: 'org.freedesktop.RealtimeKit1.service',
        configuration: config,
        install_dir: busservicedir,
)

configure_file(
        input: 'rtkit-daemon.service.in',
        output: 'rtkit-daemon.service',
        configuration: config,
        install_dir: systemunitdir,
)

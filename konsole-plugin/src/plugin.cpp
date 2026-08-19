// SPDX-License-Identifier: GPL-2.0-or-later
#include "plugin.h"

#include "MainWindow.h"
#include "bridge.h"

#include <KPluginFactory>

namespace OpenCodeBeacon
{
K_PLUGIN_CLASS_WITH_JSON(Plugin, "konsole_beacon_bridge.json")

Plugin::Plugin(QObject *parent, const QVariantList &arguments)
    : Konsole::IKonsolePlugin(parent, arguments)
{
    setName(QStringLiteral("OpenCodeBeaconActivationBridge"));
}

Plugin::~Plugin()
{
    m_bridges.clear();
}

void Plugin::createWidgetsForMainWindow(Konsole::MainWindow *mainWindow)
{
    if (mainWindow == nullptr || m_bridges.contains(mainWindow)) {
        return;
    }
    auto *bridge = new Bridge(mainWindow->viewManager(), this);
    if (!bridge->registerOnSessionBus()) {
        delete bridge;
        return;
    }
    m_bridges.insert(mainWindow, bridge);
    connect(mainWindow, &QObject::destroyed, this, [this, mainWindow]() {
        m_bridges.removeOwner(mainWindow);
    });
}

void Plugin::activeViewChanged(Konsole::SessionController *, Konsole::MainWindow *)
{
}
}

#include "plugin.moc"

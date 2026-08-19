// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <pluginsystem/IKonsolePlugin.h>

#include "owned_object_registry.h"

namespace OpenCodeBeacon
{
class Bridge;

class Plugin final : public Konsole::IKonsolePlugin
{
    Q_OBJECT

public:
    Plugin(QObject *parent, const QVariantList &arguments);
    ~Plugin() override;

    void createWidgetsForMainWindow(Konsole::MainWindow *mainWindow) override;
    void activeViewChanged(Konsole::SessionController *, Konsole::MainWindow *) override;

private:
    OwnedObjectRegistry m_bridges;
};
}

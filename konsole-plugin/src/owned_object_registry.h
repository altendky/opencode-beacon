// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <QHash>
#include <QObject>

namespace OpenCodeBeacon
{
class OwnedObjectRegistry final
{
public:
    ~OwnedObjectRegistry();

    bool contains(const QObject *owner) const;
    void insert(const QObject *owner, QObject *object);
    void removeOwner(const QObject *owner);
    void clear();

private:
    QHash<const QObject *, QObject *> m_objects;
};
}

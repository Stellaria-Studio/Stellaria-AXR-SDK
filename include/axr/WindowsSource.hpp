// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
// Fixed trusted source transport. No shell, inherited environment, parent
// conversation or reusable worker. The formal API requires the protected host.
void WindowsSourceReadiness(const Json& configuration);
Json RunWindowsSource(const Json& configuration,const std::string& input,const std::function<void()>& check);
}

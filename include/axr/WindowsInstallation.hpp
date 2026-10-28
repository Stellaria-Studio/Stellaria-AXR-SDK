// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
#pragma once
#include "Core.hpp"
namespace Stellaria::AXR {
std::filesystem::path WindowsInstallationRoot();
// Fixed hosts derive this directory from their own actual OS image, never a
// model-supplied path. Validate the complete dependency tree and ancestors.
void VerifyWindowsInstallation(const std::filesystem::path& directory);
// Content-only check for an offline staged tree; conveys no installation trust.
void VerifyWindowsRuntimeFiles(const std::filesystem::path& directory);
std::filesystem::path WindowsDataRoot();
std::filesystem::path WindowsDeploymentConfiguration();
// Native-only owner keyring migration. Never bound to Python or MCP.
std::string ReadWindowsOwnerCredential(const std::string& ownerSid,const std::string& space,const std::string& name);
}

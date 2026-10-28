# 集成与构建

AXR 提供控制面和执行原语。集成方需要实现应用注册、资源目录、来源说明、业务 handler、
精确目标验证、系统权限与结果观察。SDK 不会自行取得用户账号或应用权限。

## 原生 SDK

```sh
cmake -S . -B .local-build/dev -DCMAKE_BUILD_TYPE=Release
cmake --build .local-build/dev --parallel 4
ctest --test-dir .local-build/dev --output-on-failure
cmake --install .local-build/dev --prefix /your/sdk/prefix
```

macOS 用 Homebrew 提供 `cmake openssl@3 sqlite`；需要时添加
`-DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`。平台 helper 默认构建；核心测试可用
`-DAXR_PLATFORM_HELPERS=OFF`。安装后的 CMake 消费示例在 [examples/cmake](../examples/cmake)。

Windows 使用 Visual Studio 2022/更新版的 C++20 工具链和 Windows SDK，推荐 vcpkg 的
`openssl sqlite3 nlohmann-json`。将 vcpkg toolchain 传入 CMake；多配置构建增加
`--config Release`，CTest 增加 `-C Release`。Hello/TPM/管理员身份不在普通 CI 中模拟为真实硬件。

Linux 需要 OpenSSL/SQLite 开发包。核心可构建；macOS/Windows 的所有者硬件与安装边界
不能外推为 Linux 等效实现。未实现的平台能力应拒绝，而不是降级为同进程“安全”。

## Python

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install -e .
.venv/bin/python -m pytest tests/python
```

Windows 使用 `.venv\Scripts\python.exe`。pip 的构建会编译 C++ 原生模块；Python 代码不是
可独立替代密码学内核的实现。需要传递 OpenSSL 路径时使用 `CMAKE_ARGS`。
发布前另构建 `-DAXR_SECURITY_RELEASE=ON`，该配置禁用开发夹具和旧提交路径。
`AXR_OWNER_DEPLOYMENT` 是所有者登记路径，不表示已经完成 OS 认证或授予应用权限。

## 接入一个新应用

1. 确认主体、资源和操作，保持原始数据来源及 `untrusted-external` 标记。
2. 将读取、派生处理、对模型披露、外部写入拆成具有明确目的与目的地的操作。
3. 在可信所有者控制面审批，签发有期限/额度的能力；Agent 接口不暴露签发能力。
4. 将完整正文、目标、来源和唯一执行 ID 绑定到精确意图；执行前重新验证。
5. 在真实平台提交点核对目标和执行器身份，单次认领后只提交一次。
6. 独立观察结果。外部状态不确定时保留 Unknown，禁止以换请求 ID 等方式重复提交。
7. 将不可信模型置于实际 OS 沙箱/受控进程与有界 IPC 内，而非仅依赖提示词。

Authority Host 可作为固定嵌入宿主构建，但部署需要应用签名、受保护配置、原生密钥存储、
应用注册和平台 helper。当前安装/恢复入口保留原微信产品的兼容 profile，包括固定模块、
Windows helper 名称和登记契约。它们未被改成可由 Agent 指定模块、路径或任意程序的入口。
新产品应明确设计自己的受保护 profile，不能把这些兼容入口视为通用应用授权器。

原微信产品及其历史设备验证位于独立的
[WeChat MCP 仓库](https://github.com/666Dean/Wechat-MCP)。这些应用证据不作为 SDK 本身的通用资格。

## 性能评估

```sh
cmake -S . -B .local-build/bench -DCMAKE_BUILD_TYPE=Release -DAXR_BENCHMARKS=ON
cmake --build .local-build/bench --target axr-guard-lookup-benchmark --parallel 4
.local-build/bench/axr-guard-lookup-benchmark
```

这是一千条有效合成授权的查找微基准，不会接触账号、系统权限或真实应用。
基准与安全测试同时保留；缓存或批量优化不得跨请求复用过期的策略/证明。

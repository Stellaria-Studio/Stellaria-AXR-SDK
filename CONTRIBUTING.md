# 贡献指南

欢迎为 Stellaria AXR SDK 提交问题、测试、文档和实现改进。SDK 的核心是明确的授权边界、
可撤销的执行与可验证的证据；贡献也应说明具体行为、验证结果及适用范围。

## Stellaria CLA 1.0

代码和文档贡献采用 [Stellaria CLA 1.0](legal/Stellaria-CLA-1.0.md)。
[原始协议](legal/originals/Stellaria_CLA_1.0.docx)及其 SHA-256 记录在
[协议来源清单](legal/source-manifest.json)。

请在提交前阅读完整协议。其重点包括：对签署生效后提交、可合法处分且被正式接受的
具体贡献，按协议转让可转让的著作财产权；作者依法保留的人身权不因协议转让。
历史贡献、未接受的 PR、独立背景知识产权和第三方材料不自动转移。
已有效取得的权利可用于 AGPL 与 SCL 等授权。普通自愿贡献无偿，另有有效约定的除外。

### 贡献流程

1. 在 issue 或 PR 中说明变更范围、来源、第三方材料及重要的 AI 辅助使用情况。
2. 向维护者申请 CLA 签署流程。先核对实际受让方的法律主体及可信的私密交接渠道；
   组织贡献还需确认签署代表权限和实际创作者的权利链。
3. 双方通过有效签署或具备充分身份认证与可核验同意记录的合法方式完成协议。
   **普通勾选、GitHub 昵称、DCO、PR 评论或提交代码本身不替代有效签约。**
4. 维护者核对协议版本、身份、权限与贡献范围，在私密记录中关联 PR、准确提交哈希、
   文件、时间及接受记录。新增作者或权利范围变化时重新核对。
5. 完成技术审查、测试和权利检查后接受贡献。签署及权利证据未核验时不合并；
   技术合并不能替代缺失的第三方权利。

本仓库采用维护者人工核验流程，未宣称部署自动电子签约服务。签署材料、真实身份、
证件和个人联系方式不应上传到公开 issue、PR、Git 或 Actions 产物。
维护者仅公开必要的贡献署名/流程状态；私密材料按最小必要原则保存。
商业合作本身不意味着已经签署 CLA。

## 开发和测试

```sh
cmake -S . -B .local-build/dev -DCMAKE_BUILD_TYPE=Release
cmake --build .local-build/dev --parallel 4
ctest --test-dir .local-build/dev --output-on-failure

python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install -e .
.venv/bin/python -m pytest tests/python
```

正式配置另用 `-DAXR_SECURITY_RELEASE=ON` 构建和测试。夹具配置用于合成状态，不能
用于发布。系统认证与真实硬件测试只能由设备所有者本人完成；普通回归不触发这些操作。

安全相关修改应覆盖成功和拒绝路径，尤其是过期、额度、撤权、来源、精确意图、
进程身份、篡改及 Unknown 不重试。请附可复现命令；微基准和真实应用性能分开报告。
新依赖需记录来源、固定版本/摘要和许可证。避免无证据地改写密码学或安全策略。

每个 PR 更新 CHANGELOG.md，并区分实现、合成验证、OS/硬件验证与应用端到端验证。
私钥、部署配置、数据库和真实个人数据永不进入提交。安全漏洞请遵循 [SECURITY.md](SECURITY.md)。

<p align="center">
  <a href="../../SECURITY.md">Русский</a> · <a href="../en/SECURITY.md">English</a> · <strong>简体中文</strong>
</p>

# 安全策略

Hydrat 团队高度重视网关安全、用户隐私和流量隔离。

---

## 支持的版本

| 版本 | 支持状态 |
| :--- | :--- |
| `main`（当前版本） | :white_check_mark: |

关键安全修复会及时发布到 `main` 分支。

---

## 报告漏洞

如果你在 Hydrat 中发现安全漏洞：

1. **不要创建公开 Issue** 来描述漏洞或利用方法。
2. 请通过 [GitHub Security Advisory](https://github.com/only-hydrat/hydrat/security/advisories/new) 提交报告，或发送邮件至维护者 only_hydrat@proton.me。
3. 报告中应包含：
   - 问题说明及潜在影响；
   - 复现步骤或概念验证；
   - 受影响的组件和配置。
4. 我们将在 48 小时内回复，并在公开披露前协调修复发布时间。

---

## Hydrat 的安全架构

Hydrat 遵循纵深防御原则：

- **限制密钥文件权限：**包含私钥的配置文件（例如 `wg0.conf` 和 `.env`）以 `0600` 权限创建和读取。
- **只读容器：**controller 使用只读根文件系统（`read_only: true`），临时文件存放在隔离的 `tmpfs` 中。
- **无默认密码：**管理面板密码不会写入镜像或配置。Controller 必须显式设置高强度 `HYDRAT_ADMIN_PASSWORD`，缺少该变量时启动失败。
- **俄罗斯出口泄露保护：**`disallow_ru_egress` 会排除位于俄罗斯境内的出口节点，降低敏感流量被去匿名化或封锁的风险。
- **Gateway 权限：**gateway 保留 Docker 默认 capabilities，并显式添加 `NET_ADMIN` 和 `NET_RAW`；容器不以 `privileged` 模式运行。这并非最小权限配置，因为 WireGuard、路由、nftables、端口以及绑定挂载存储的初始化需要这些权限。
